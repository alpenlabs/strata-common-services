//! Core prover: fetches input via spec, proves via strategy,
//! optionally stores receipt and calls domain hook.

use std::{collections::HashMap, fmt, num::NonZeroUsize, slice, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::{
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    task::spawn_blocking,
};
use tracing::{debug, error, info, info_span, warn, Instrument};
use zkaleido::ZkVmHost;
#[cfg(feature = "remote")]
use zkaleido::ZkVmRemoteHost;

use crate::{
    config::{ProverConfig, RetryConfig},
    error::{FailureAction, ProverError, ProverResult},
    in_memory::InMemoryTaskStore,
    strategy::NativeStrategy,
    task::{now_secs, AttemptCounts, TaskRecord, TaskResult, TaskStatus},
    traits::{
        InputResolution, ProofSpec, ProveContext, ProveStrategy, ReceiptHook, ReceiptStore,
        TaskStore,
    },
};

/// One completion-notification sender per pending `wait_for_tasks` caller.
///
/// Each waiter receives a private `oneshot::Receiver`; [`Prover::notify`]
/// drains and removes the entry when the task reaches a terminal state.
type WatcherMap<T> = HashMap<Vec<u8>, Vec<oneshot::Sender<TaskResult<T>>>>;

/// Recheck cadence for a blocked task when no retry config is present and the
/// spec gave no per-task override. Real consumers configure
/// `RetryConfig::blocked_recheck_secs`; this is only a floor.
const DEFAULT_BLOCKED_RECHECK_SECS: u64 = 10;

/// Shared limit on concurrent proof input preparation and submission.
///
/// A task takes one unit of capacity before it prepares its input. Native
/// proving holds the unit until the blocking proof returns. Remote proving
/// releases it once a new proof ID is saved, or a saved one is accepted, before
/// polling, so the budget does not limit how many remote proofs run at once.
/// Receipt storage and receipt hooks run without capacity.
///
/// Clone one budget into every prover that should share it. A task that finds
/// no capacity stays a durable `Pending` row until a later [`Prover::tick`]
/// starts it; no task waits in memory for capacity.
#[derive(Clone, Debug)]
pub struct ConcurrencyBudget(Arc<Semaphore>);

impl ConcurrencyBudget {
    /// Creates a budget of `max` concurrent preparations and submissions.
    ///
    /// # Panics
    ///
    /// Panics if `max` exceeds [`Semaphore::MAX_PERMITS`].
    pub fn new(max: NonZeroUsize) -> Self {
        Self(Arc::new(Semaphore::new(max.get())))
    }

    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.0.clone().try_acquire_owned().ok()
    }

    fn is_exhausted(&self) -> bool {
        self.0.available_permits() == 0
    }
}

/// State guarded by the dispatch lock, which serializes startup recovery with
/// every task start from [`Prover::submit`] and [`Prover::tick`].
#[derive(Debug, Default)]
struct DispatchState {
    /// Whether startup recovery has completed. It stays unset after a failed
    /// recovery, so the next submit or tick runs recovery again before
    /// starting any work.
    recovered: bool,
}

/// Single-proof-type prover.
///
/// Generic over `H` (spec) only. The zkVM host type is erased inside
/// the `ProveStrategy` — consumers never see it.
pub struct Prover<H: ProofSpec> {
    spec: Arc<H>,
    strategy: Arc<dyn ProveStrategy<H>>,
    config: ProverConfig,
    task_store: Arc<dyn TaskStore>,
    receipt_store: Option<Arc<dyn ReceiptStore>>,
    receipt_hook: Option<Arc<dyn ReceiptHook<H>>>,
    /// Oneshot senders for notifying waiters when tasks reach terminal states.
    watchers: Arc<Mutex<WatcherMap<H::Task>>>,
    concurrency_budget: Option<ConcurrencyBudget>,
    dispatch: Mutex<DispatchState>,
}

impl<H: ProofSpec> fmt::Debug for Prover<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prover")
            .field("has_retry", &self.config.retry.is_some())
            .field("has_receipt_store", &self.receipt_store.is_some())
            .field("has_receipt_hook", &self.receipt_hook.is_some())
            .field("has_concurrency_budget", &self.concurrency_budget.is_some())
            .finish()
    }
}

// Prover is never cloned directly. Spawning methods take `self: &Arc<Self>`
// so background tasks hold a cheap Arc refcount instead of shallow-cloning
// every field. External consumers go through ProverHandle, which already
// stores an `Arc<Prover>`.

// ============================================================================
// Consumer API
// ============================================================================

impl<H: ProofSpec> Prover<H> {
    /// Registers a task and starts it when capacity allows. Idempotent.
    ///
    /// A task that finds no capacity stays a durable `Pending` row until
    /// [`Self::tick`] starts it, so a prover with a [`ConcurrencyBudget`] must
    /// be ticked. Submitting a task that already exists starts it only if it
    /// is `Pending` or its retry is due, which is what the next tick would do.
    pub async fn submit(self: &Arc<Self>, task: H::Task) -> ProverResult<()> {
        let key: Vec<u8> = task.clone().into();
        let mut dispatch = self.dispatch.lock();
        self.ensure_recovered(&mut dispatch)?;
        if self.task_store.get(&key)?.is_none() {
            self.task_store
                .insert(TaskRecord::new(key.clone(), TaskStatus::Pending))?;
        }
        self.try_start_task(task, key)
    }

    /// Submit a task and block until it reaches a terminal state.
    pub async fn execute(self: &Arc<Self>, task: H::Task) -> ProverResult<TaskResult<H::Task>> {
        self.submit(task.clone()).await?;
        let results = self.wait_for_tasks(slice::from_ref(&task)).await?;
        Ok(results.into_iter().next().expect("one result for one task"))
    }

    /// Block until all tasks reach terminal states.
    ///
    /// Zero polling: each waiter receives a private `oneshot` receiver that
    /// fires exactly once when the task reaches a terminal state. The
    /// subscribe-or-observe-completion step is linearized against
    /// `Self::notify` via the watchers mutex, so the wait cannot miss
    /// completions that race with subscription.
    pub async fn wait_for_tasks(
        &self,
        tasks: &[H::Task],
    ) -> ProverResult<Vec<TaskResult<H::Task>>> {
        let mut results: Vec<Option<TaskResult<H::Task>>> = vec![None; tasks.len()];
        let mut pending: Vec<(usize, oneshot::Receiver<TaskResult<H::Task>>)> = Vec::new();

        for (i, task) in tasks.iter().enumerate() {
            let key: Vec<u8> = task.clone().into();

            // Hold the watchers lock across the store check + subscribe so
            // we cannot miss a notification that races with this decision.
            let mut w = self.watchers.lock();
            if let Some(record) = self.task_store.get(&key)? {
                if let Some(r) = terminal_result(task, record.status()) {
                    results[i] = Some(r);
                    continue;
                }
            }
            let (tx, rx) = oneshot::channel();
            w.entry(key).or_default().push(tx);
            drop(w);

            pending.push((i, rx));
        }

        for (i, rx) in pending {
            // `rx.await` can only fail if the sender was dropped without
            // sending — we never do that: `notify` drains the entry on
            // completion, and the entry is only created here. Treat a dropped
            // sender as a permanent-failure signal rather than panicking.
            match rx.await {
                Ok(result) => results[i] = Some(result),
                Err(_) => {
                    results[i] = Some(TaskResult::failed(
                        tasks[i].clone(),
                        "notification sender dropped".to_string(),
                    ));
                }
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    /// Get a receipt from the receipt store by task.
    ///
    /// Returns `None` if the store has no receipt for this task, or `Err` if
    /// no receipt store was configured.
    pub fn get_receipt(
        &self,
        task: &H::Task,
    ) -> ProverResult<Option<zkaleido::ProofReceiptWithMetadata>> {
        let key: Vec<u8> = task.clone().into();
        self.receipt_store
            .as_ref()
            .ok_or(ProverError::NoReceiptStore)?
            .get(&key)
    }
}

// ============================================================================
// Internals - PaaS wiring + proving flow (not exposed on ProverHandle)
// ============================================================================

impl<H: ProofSpec> Prover<H> {
    pub fn has_retry(&self) -> bool {
        self.config.retry.is_some()
    }

    /// Whether the prover needs periodic ticks: retries and dependency
    /// rechecks fire, and capacity-limited tasks start, only on a tick.
    pub fn needs_tick(&self) -> bool {
        self.has_retry() || self.concurrency_budget.is_some()
    }

    pub fn has_receipt_store(&self) -> bool {
        self.receipt_store.is_some()
    }

    pub fn task_store(&self) -> &dyn TaskStore {
        self.task_store.as_ref()
    }

    /// Current task status by task.
    pub fn get_status(&self, task: &H::Task) -> ProverResult<TaskStatus> {
        let key: Vec<u8> = task.clone().into();
        self.task_store
            .get(&key)?
            .map(|r| r.status().clone())
            .ok_or_else(|| ProverError::TaskNotFound(format!("{task}")))
    }

    /// Starts `Pending` tasks and due retries and rechecks while capacity
    /// allows. Called by PaaS on its tick interval.
    pub async fn tick(self: &Arc<Self>) {
        if let Err(e) = self.dispatch_tasks() {
            warn!(%e, "failed to dispatch proof tasks; will retry next tick");
        }
    }

    /// Starts runnable tasks while the budget has room.
    ///
    /// The order is not a priority policy. `Pending` rows are tried before due
    /// `TransientFailure` and `Blocked` rows, each group in the task store's
    /// listing order (key order for the sled and MDBX stores, where EE chunk
    /// keys are block hashes rather than chain order). Under a small budget
    /// with native proving, new work can therefore run before older retries.
    /// Remote proving holds capacity only until submission, so the effect
    /// there is limited to preparation time.
    ///
    /// A failure to start one row is logged and does not stop the others.
    fn dispatch_tasks(self: &Arc<Self>) -> ProverResult<()> {
        let mut dispatch = self.dispatch.lock();
        self.ensure_recovered(&mut dispatch)?;
        // Every start needs capacity, so skip the store scans while none is free.
        if self.budget_exhausted() {
            return Ok(());
        }
        let mut runnable = self.task_store.list_unfinished()?;
        runnable.retain(|record| matches!(record.status(), TaskStatus::Pending));
        runnable.extend(self.task_store.list_retriable(now_secs())?);
        for record in runnable {
            if self.budget_exhausted() {
                break;
            }
            let key = record.key().to_vec();
            if let Some(task) = decode_task_key::<H>(&key) {
                if let Err(e) = self.try_start_task(task, key) {
                    warn!(%e, key = ?record.key(), "failed to start proof task; will retry next tick");
                }
            }
        }
        Ok(())
    }

    fn budget_exhausted(&self) -> bool {
        self.concurrency_budget
            .as_ref()
            .is_some_and(ConcurrencyBudget::is_exhausted)
    }

    /// Runs startup recovery once, before any task starts.
    ///
    /// A `Proving` row found here belongs to an attempt that died with the
    /// previous process (OOM, SIGKILL, panic) before any error path could run.
    /// Recovery counts that death as a resume-class failure, so a task that
    /// keeps killing the process cannot rerun forever: it gets a retry after
    /// backoff, or `PermanentFailure` once `max_retries` is spent. `Pending`
    /// rows need nothing here; dispatch starts them under the budget.
    ///
    /// A failed scan or write leaves recovery incomplete, and the next submit
    /// or tick runs it again before starting any work.
    fn ensure_recovered(&self, dispatch: &mut DispatchState) -> ProverResult<()> {
        if dispatch.recovered {
            return Ok(());
        }
        for record in self.task_store.list_unfinished()? {
            let TaskStatus::Proving { counts } = record.status() else {
                continue;
            };
            let key = record.key();
            warn!(
                ?key,
                retry_count = counts.retry.saturating_add(1),
                "task died mid-Proving; scheduling resume-class retry"
            );
            let status = self.schedule_retry(key, "process died mid-Proving", *counts, false)?;
            if let Some(task) = decode_task_key::<H>(key) {
                self.notify(key, &task, &status);
            }
        }
        dispatch.recovered = true;
        Ok(())
    }

    /// Starts `task` if its row is runnable and capacity allows.
    ///
    /// Called with the dispatch lock held, so the row is `Proving` before any
    /// other caller can see it as runnable.
    fn try_start_task(self: &Arc<Self>, task: H::Task, key: Vec<u8>) -> ProverResult<()> {
        let Some(record) = self.task_store.get(&key)? else {
            return Ok(());
        };
        let status = record.status();
        let runnable = matches!(status, TaskStatus::Pending)
            || (status.wants_rescan()
                && record.retry_after_secs().is_some_and(|at| at <= now_secs()));
        if !runnable {
            return Ok(());
        }
        let permit = match &self.concurrency_budget {
            Some(budget) => match budget.try_acquire() {
                Some(permit) => Some(permit),
                None => return Ok(()),
            },
            None => None,
        };
        // The status carries the attempt counters, so they survive a crash
        // that recovery later counts as a failed attempt.
        self.task_store.update_status(
            &key,
            TaskStatus::Proving {
                counts: status.counts(),
            },
        )?;
        let prover = Arc::clone(self);
        tokio::spawn(async move {
            prover.run_task(task, key, record, permit).await;
        });
        Ok(())
    }

    /// Runs one attempt of a task that dispatch has marked `Proving`.
    ///
    /// `record` is the row as dispatch found it, before the `Proving`
    /// overwrite, so it still carries the attempt counters and any saved remote
    /// proof ID. `permit` is the task's unit of submission capacity, if the
    /// prover has a budget.
    async fn run_task(
        &self,
        task: H::Task,
        key: Vec<u8>,
        record: TaskRecord,
        permit: Option<OwnedSemaphorePermit>,
    ) {
        let counts = record.status().counts();
        let saved_metadata = record.metadata().map(<[u8]>::to_vec);
        let span = info_span!("prove", task = %task);

        async {
            // Stage checkpoint: if proving already succeeded on a prior attempt
            // the receipt is in the receipt store. Skip resolve_input and the
            // (expensive) prove, and re-run only the post-prove hook + finish —
            // so a transient receipt-hook failure never triggers a re-prove.
            // Only applies to provers with a receipt store configured.
            if let Some(receipt_store) = self.receipt_store.as_ref() {
                match receipt_store.get(&key) {
                    Ok(Some(receipt)) => {
                        // A stored receipt needs no input preparation or submission.
                        drop(permit);
                        debug!("receipt already persisted; skipping prove, running hook only");
                        if let Some(hook) = &self.receipt_hook {
                            if let Err(e) = hook.on_receipt(&task, &receipt).await {
                                error!(%e, "receipt hook failed (checkpoint path)");
                                self.settle(&key, &task, self.handle_error(&key, &e, counts));
                                return;
                            }
                        }
                        info!("task completed (from checkpointed receipt)");
                        self.settle(&key, &task, self.write_status(&key, TaskStatus::Completed));
                        return;
                    }
                    // No checkpoint yet — fall through to a full prove.
                    Ok(None) => {}
                    Err(e) => {
                        // A transient receipt-store read must NOT be swallowed
                        // as "no receipt": that would fall through and re-run
                        // the (possibly remote, expensive) prove after a prior
                        // success. Classify it (Storage -> RetryResume) and
                        // retry the checkpoint instead.
                        error!(%e, "receipt store read failed on checkpoint path");
                        self.settle(&key, &task, self.handle_error(&key, &e, counts));
                        return;
                    }
                }
            }

            // A saved proof ID the strategy can resume means the proof was
            // already submitted. Poll it without preparing input that would be
            // discarded, and free the submission capacity at once.
            let resume = saved_metadata
                .as_deref()
                .is_some_and(|saved| self.strategy.can_resume(saved));
            let permit = permit.filter(|_| !resume);

            // 1. Resolve input: ready, blocked on a dependency, or rejected.
            let resolution = if resume {
                None
            } else {
                Some(self.spec.resolve_input(&task).await)
            };
            let input = match resolution {
                None => None,
                Some(Ok(InputResolution::Ready(input))) => Some(input),
                Some(Ok(InputResolution::Blocked {
                    reason,
                    recheck_after,
                })) => {
                    // Not a failure — park and recheck without notifying waiters
                    // or touching the retry budget (but bounded by the backstop).
                    let outcome = self.park_blocked(&key, reason, recheck_after, counts);
                    self.settle(&key, &task, outcome);
                    return;
                }
                Some(Ok(InputResolution::Rejected { reason })) => {
                    error!(%reason, "input rejected");
                    let status = TaskStatus::PermanentFailure { error: reason };
                    self.settle(&key, &task, self.write_status(&key, status));
                    return;
                }
                Some(Err(e)) => {
                    error!(%e, "resolve_input failed");
                    self.settle(&key, &task, self.handle_error(&key, &e, counts));
                    return;
                }
            };

            // 2. Prove (blocking — strategy handles native vs remote)
            let store = self.task_store.clone();
            let persist_key = key.clone();
            let ctx = ProveContext::new(
                saved_metadata,
                move |data| {
                    if let Err(e) = store.set_metadata(&persist_key, data) {
                        error!(
                            %e,
                            "failed to save remote proof ID; a restart before completion resubmits the proof"
                        );
                    }
                },
                permit,
            );

            let strategy = self.strategy.clone();
            let prove_result = spawn_blocking(move || match input {
                Some(input) => strategy.prove(&input, ctx),
                None => strategy.resume(ctx),
            })
            .await;

            let receipt = match prove_result {
                Ok(Ok(receipt)) => receipt,
                Ok(Err(e)) => {
                    error!(%e, "prove failed");
                    self.settle(&key, &task, self.handle_error(&key, &e, counts));
                    return;
                }
                Err(e) => {
                    error!(%e, "prove task panicked");
                    let status = TaskStatus::PermanentFailure {
                        error: e.to_string(),
                    };
                    self.settle(&key, &task, self.write_status(&key, status));
                    return;
                }
            };

            // 3. Store receipt (if configured)
            if let Some(store) = &self.receipt_store {
                if let Err(e) = store.put(&key, &receipt) {
                    error!(%e, "receipt store put failed");
                    self.settle(&key, &task, self.handle_error(&key, &e, counts));
                    return;
                }
            }

            // 4. Domain hook (if configured)
            if let Some(hook) = &self.receipt_hook {
                if let Err(e) = hook.on_receipt(&task, &receipt).await {
                    error!(%e, "receipt hook failed");
                    self.settle(&key, &task, self.handle_error(&key, &e, counts));
                    return;
                }
            }

            // 5. Done
            info!("task completed");
            self.settle(&key, &task, self.write_status(&key, TaskStatus::Completed));
        }
        .instrument(span)
        .await;
    }

    /// Ends an attempt: tells waiters about a recorded terminal status, or
    /// logs a failed write.
    ///
    /// A failed write leaves the row `Proving`, which restart recovery treats
    /// as an interrupted attempt. Waiters only ever hear outcomes the task
    /// store holds.
    fn settle(&self, key: &[u8], task: &H::Task, outcome: ProverResult<TaskStatus>) {
        match outcome {
            Ok(status) => self.notify(key, task, &status),
            Err(e) => error!(
                %e,
                "failed to record proof task outcome; restart recovery will retry the task"
            ),
        }
    }

    /// Writes `status` and returns it for [`Self::settle`].
    fn write_status(&self, key: &[u8], status: TaskStatus) -> ProverResult<TaskStatus> {
        self.task_store.update_status(key, status.clone())?;
        Ok(status)
    }

    /// Park a task that is waiting on an input dependency.
    ///
    /// Sets [`TaskStatus::Blocked`] and schedules a steady recheck via
    /// `retry_after`. Does not touch the retry/resubmit counters or notify
    /// waiters — blocking is an expected wait, not a failure, so the scanner
    /// re-spawns it (via [`TaskStatus::wants_rescan`]) when the recheck is due.
    /// `counts` is the [`AttemptCounts`] the row carried before this attempt;
    /// `park_blocked` bumps only `recheck` and preserves `retry`/`resubmit`, so
    /// a `Blocked` wait interleaved with transient failures keeps every budget
    /// bounded. Once `recheck` exceeds [`RetryConfig::max_blocked_rechecks`]
    /// the dependency is treated as never going to materialize: the task is
    /// promoted to `PermanentFailure`, rather than rechecking — and hanging —
    /// forever.
    fn park_blocked(
        &self,
        key: &[u8],
        reason: String,
        recheck_after: Option<Duration>,
        counts: AttemptCounts,
    ) -> ProverResult<TaskStatus> {
        let counts = AttemptCounts {
            recheck: counts.recheck.saturating_add(1),
            ..counts
        };

        // Safety backstop: give up on a dependency that never resolves.
        if let Some(max) = self.config.retry.as_ref().map(|c| c.max_blocked_rechecks) {
            if counts.recheck > max {
                warn!(
                    reason,
                    recheck_count = counts.recheck,
                    max,
                    "blocked dependency unresolved; marking PermanentFailure"
                );
                let status = TaskStatus::PermanentFailure {
                    error: format!("blocked dependency unresolved after {max} rechecks: {reason}"),
                };
                return self.write_status(key, status);
            }
        }

        let secs = recheck_after.map(|d| d.as_secs()).unwrap_or_else(|| {
            self.config
                .retry
                .as_ref()
                .map_or(DEFAULT_BLOCKED_RECHECK_SECS, |c| c.blocked_recheck_secs)
        });
        debug!(
            reason,
            recheck_secs = secs,
            recheck_count = counts.recheck,
            "task blocked on dependency"
        );
        // The deadline goes in before the status: if the status write then
        // fails, the row stays `Proving` for restart recovery instead of
        // becoming `Blocked` with a stale or missing deadline.
        self.task_store
            .set_retry_after(key, now_secs().saturating_add(secs))?;
        self.write_status(key, TaskStatus::Blocked { reason, counts })
    }

    /// Persist the outcome of a failed attempt and return the status written,
    /// so the caller can hand it to [`Self::notify`] without a fallible re-read.
    fn handle_error(
        &self,
        key: &[u8],
        err: &ProverError,
        counts: AttemptCounts,
    ) -> ProverResult<TaskStatus> {
        match err.action() {
            FailureAction::RetryResume => self.schedule_retry(key, &err.to_string(), counts, false),
            FailureAction::RetryFresh => self.schedule_retry(key, &err.to_string(), counts, true),
            FailureAction::Permanent => self.write_status(
                key,
                TaskStatus::PermanentFailure {
                    error: err.to_string(),
                },
            ),
        }
    }

    /// Schedule a retry after backoff.
    ///
    /// Resume-class retries (`fresh == false`) re-poll the same request and
    /// draw from `max_retries`. Resubmit-class retries (`fresh == true`) drop
    /// the saved remote metadata so the next attempt submits a fresh request,
    /// and draw from the smaller `max_resubmits` budget since each one re-runs
    /// the whole proof. When the relevant budget is exhausted the task becomes
    /// `PermanentFailure`. Backoff is keyed on whichever counter advanced.
    ///
    /// The metadata clear and the deadline are written before the status, and
    /// the first failed write stops the sequence. The row then stays `Proving`
    /// for restart recovery rather than becoming a retry that no scan picks up.
    fn schedule_retry(
        &self,
        key: &[u8],
        msg: &str,
        counts: AttemptCounts,
        fresh: bool,
    ) -> ProverResult<TaskStatus> {
        if let Some(ref cfg) = self.config.retry {
            // Bump only the advancing counter; the others (including `recheck`)
            // carry through so an interleaved Blocked/transient sequence stays
            // bounded by every ceiling.
            let (new_counts, within_budget, attempt) = if fresh {
                let n = counts.resubmit.saturating_add(1);
                (
                    AttemptCounts {
                        resubmit: n,
                        ..counts
                    },
                    cfg.should_resubmit(n),
                    n,
                )
            } else {
                let n = counts.retry.saturating_add(1);
                (AttemptCounts { retry: n, ..counts }, cfg.should_retry(n), n)
            };

            if within_budget {
                if fresh {
                    // Drop the dead remote ProofId so the next attempt resubmits.
                    self.task_store.clear_metadata(key)?;
                }
                warn!(
                    retry_count = new_counts.retry,
                    resubmit_count = new_counts.resubmit,
                    recheck_count = new_counts.recheck,
                    fresh,
                    error = %msg,
                    "scheduling retry"
                );
                let delay_secs = cfg.jittered_delay_secs(attempt, jitter_seed(key, attempt));
                self.task_store
                    .set_retry_after(key, now_secs().saturating_add(delay_secs))?;
                return self.write_status(
                    key,
                    TaskStatus::TransientFailure {
                        counts: new_counts,
                        error: msg.to_string(),
                    },
                );
            }
        }

        self.write_status(
            key,
            TaskStatus::PermanentFailure {
                error: format!("retries exhausted: {msg}"),
            },
        )
    }

    /// Fan out the terminal result to every pending waiter and remove the
    /// watcher entry so the map does not grow unbounded.
    ///
    /// Takes the freshly-persisted `status` from the caller rather than
    /// re-reading the store: a transient store read here previously turned into
    /// `None` and bailed *without draining the watchers*, permanently losing an
    /// otherwise terminal notification and hanging every waiter forever. Since
    /// every caller has just written the terminal status, the read was both
    /// fallible and redundant.
    ///
    /// The watchers lock is held across the drain to linearize with
    /// [`Self::wait_for_tasks`], which performs its
    /// check-terminal-then-subscribe decision under the same lock. The caller
    /// persists the terminal status *before* invoking this, so a concurrent
    /// subscriber either observes terminal in the store (and returns without
    /// subscribing) or is drained here.
    fn notify(&self, key: &[u8], task: &H::Task, status: &TaskStatus) {
        let Some(result) = terminal_result(task, status) else {
            // Non-terminal (e.g. a scheduled TransientFailure): waiters keep
            // waiting for a later terminal notification.
            return;
        };
        let mut w = self.watchers.lock();
        if let Some(senders) = w.remove(key) {
            for tx in senders {
                let _ = tx.send(result.clone());
            }
        }
    }
}

/// Deterministic per-task backoff seed (FNV-1a over the key, mixed with the
/// attempt count). Used to jitter retry delays so distinct tasks that failed on
/// the same tick spread their wake-ups instead of retrying in lockstep.
fn jitter_seed(key: &[u8], retry_count: u32) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in key {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.wrapping_add(u64::from(retry_count))
}

/// Decode a storage key back into a typed task.
///
/// Logs and returns `None` on decode failure rather than panicking — a
/// corrupt or schema-drifted key should not take down the prover.
fn decode_task_key<H: ProofSpec>(key: &[u8]) -> Option<H::Task> {
    match H::Task::try_from(key.to_vec()) {
        Ok(task) => Some(task),
        Err(_) => {
            warn!(key = ?key, "failed to decode task key, skipping");
            None
        }
    }
}

/// Map a task status to a terminal [`TaskResult`] if it represents one.
fn terminal_result<T: Clone>(task: &T, status: &TaskStatus) -> Option<TaskResult<T>> {
    match status {
        TaskStatus::Completed => Some(TaskResult::completed(task.clone())),
        TaskStatus::PermanentFailure { error } => {
            Some(TaskResult::failed(task.clone(), error.clone()))
        }
        _ => None,
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builds a [`Prover`].
pub struct ProverBuilder<H: ProofSpec> {
    spec: H,
    task_store: Option<Arc<dyn TaskStore>>,
    receipt_store: Option<Arc<dyn ReceiptStore>>,
    receipt_hook: Option<Arc<dyn ReceiptHook<H>>>,
    retry: Option<RetryConfig>,
    concurrency_budget: Option<ConcurrencyBudget>,
}

impl<H: ProofSpec> ProverBuilder<H> {
    pub fn new(spec: H) -> Self {
        Self {
            spec,
            task_store: None,
            receipt_store: None,
            receipt_hook: None,
            retry: None,
            concurrency_budget: None,
        }
    }

    /// Sets storage for the task-key namespace this prover exclusively owns.
    /// See [`TaskStore`] for the ownership requirement.
    pub fn task_store(mut self, store: impl TaskStore + 'static) -> Self {
        self.task_store = Some(Arc::new(store));
        self
    }

    /// Opt-in receipt persistence. Enables `get_receipt` on the PaaS handle.
    pub fn receipt_store(mut self, store: impl ReceiptStore + 'static) -> Self {
        self.receipt_store = Some(Arc::new(store));
        self
    }

    /// Opt-in domain hook called after receipt storage.
    pub fn receipt_hook(mut self, hook: impl ReceiptHook<H> + 'static) -> Self {
        self.receipt_hook = Some(Arc::new(hook));
        self
    }

    pub fn retry(mut self, config: RetryConfig) -> Self {
        // Sanitize on ingestion so an out-of-range operator config (e.g.
        // `jitter_frac > 1.0`) can't reach the scheduler and collapse the
        // backoff to zero. This is the single choke point every config passes
        // through.
        self.retry = Some(config.sanitized());
        self
    }

    /// Limits concurrent input preparation and submission to a budget shared
    /// with every prover given a clone of it.
    ///
    /// Without a budget, every submitted task starts at once. With one, tasks
    /// beyond it wait as `Pending` rows that only [`Prover::tick`] starts.
    pub fn concurrency_budget(mut self, budget: ConcurrencyBudget) -> Self {
        self.concurrency_budget = Some(budget);
        self
    }

    /// Build with a native host (blocking `Program::prove` via `spawn_blocking`).
    pub fn native<Host: ZkVmHost + Send + Sync + 'static>(self, host: Host) -> Prover<H> {
        self.build(Arc::new(NativeStrategy::new(host)))
    }

    /// Build with a remote host (`start_proving` + poll on a long-lived runtime).
    #[cfg(feature = "remote")]
    pub fn remote<Host>(self, host: Host) -> Prover<H>
    where
        Host: ZkVmRemoteHost + Send + Sync + 'static,
    {
        use crate::strategy::RemoteStrategy;
        let local = self
            .retry
            .as_ref()
            .map(|r| r.local.clone())
            .unwrap_or_default();
        self.build(Arc::new(RemoteStrategy::new(
            host,
            Duration::from_secs(10),
            local,
        )))
    }

    /// Build with a remote host and custom poll interval.
    #[cfg(feature = "remote")]
    pub fn remote_with_interval<Host>(self, host: Host, poll_interval: Duration) -> Prover<H>
    where
        Host: ZkVmRemoteHost + Send + Sync + 'static,
    {
        use crate::strategy::RemoteStrategy;
        let local = self
            .retry
            .as_ref()
            .map(|r| r.local.clone())
            .unwrap_or_default();
        self.build(Arc::new(RemoteStrategy::new(host, poll_interval, local)))
    }

    fn build(self, strategy: Arc<dyn ProveStrategy<H>>) -> Prover<H> {
        Prover {
            spec: Arc::new(self.spec),
            strategy,
            config: ProverConfig { retry: self.retry },
            task_store: self
                .task_store
                .unwrap_or_else(|| Arc::new(InMemoryTaskStore::new())),
            receipt_store: self.receipt_store,
            receipt_hook: self.receipt_hook,
            watchers: Arc::new(Mutex::new(HashMap::new())),
            concurrency_budget: self.concurrency_budget,
            dispatch: Mutex::new(DispatchState::default()),
        }
    }
}

impl<H: ProofSpec> fmt::Debug for ProverBuilder<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverBuilder").finish()
    }
}

#[cfg(test)]
#[path = "concurrency_tests.rs"]
mod concurrency_tests;

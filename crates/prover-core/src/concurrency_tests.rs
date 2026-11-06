use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread,
};

use async_trait::async_trait;
use tokio::{sync::Semaphore, task::yield_now, time::timeout};
use zkaleido::{
    ProofReceiptWithMetadata, ProofType, PublicValues, ZkVmInputBuilder, ZkVmInputResult,
    ZkVmProgram, ZkVmResult,
};
use zkaleido_native_adapter::NativeHost;

use super::*;
use crate::InMemoryReceiptStore;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Task(u8);
impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl From<Task> for Vec<u8> {
    fn from(t: Task) -> Self {
        vec![t.0]
    }
}
impl TryFrom<Vec<u8>> for Task {
    type Error = ();
    fn try_from(bytes: Vec<u8>) -> Result<Self, ()> {
        if bytes.len() == 1 {
            Ok(Self(bytes[0]))
        } else {
            Err(())
        }
    }
}
struct Program;
impl ZkVmProgram for Program {
    type Input = ();
    type Output = ();
    fn name() -> String {
        "concurrency-test".into()
    }
    fn proof_type() -> ProofType {
        ProofType::Core
    }
    fn prepare_input<'a, B: ZkVmInputBuilder<'a>>(_: &'a ()) -> ZkVmInputResult<B::Input> {
        B::new().build()
    }
    fn process_output<H: ZkVmHost>(_: &PublicValues) -> ZkVmResult<()> {
        Ok(())
    }
}

/// Counts input resolutions and holds each one until the test adds a permit.
struct Spec {
    entered: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
    blocked: bool,
}
#[async_trait]
impl ProofSpec for Spec {
    type Task = Task;
    type Program = Program;
    async fn resolve_input(&self, _: &Task) -> ProverResult<InputResolution<()>> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        if self.blocked {
            return Ok(InputResolution::Blocked {
                reason: "dependency".into(),
                recheck_after: None,
            });
        }
        self.gate.acquire().await.unwrap().forget();
        Ok(InputResolution::Ready(()))
    }
}
struct Strategy;
impl ProveStrategy<Spec> for Strategy {
    fn prove(&self, _: &(), _ctx: ProveContext) -> ProverResult<ProofReceiptWithMetadata> {
        Ok(ProofReceiptWithMetadata::default())
    }
}
fn spec(blocked: bool) -> (Spec, Arc<AtomicUsize>, Arc<Semaphore>) {
    let entered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Semaphore::new(0));
    let spec = Spec {
        entered: entered.clone(),
        gate: gate.clone(),
        blocked,
    };
    (spec, entered, gate)
}
fn build(
    store: Arc<impl TaskStore>,
    blocked: bool,
) -> (Arc<Prover<Spec>>, Arc<AtomicUsize>, Arc<Semaphore>) {
    let (spec, entered, gate) = spec(blocked);
    let prover = ProverBuilder::new(spec)
        .task_store(store)
        .build(Arc::new(Strategy));
    (Arc::new(prover), entered, gate)
}
fn build_limited(
    budget: ConcurrencyBudget,
    store: Arc<impl TaskStore>,
    blocked: bool,
) -> (Arc<Prover<Spec>>, Arc<AtomicUsize>, Arc<Semaphore>) {
    let (spec, entered, gate) = spec(blocked);
    let prover = ProverBuilder::new(spec)
        .task_store(store)
        .concurrency_budget(budget)
        .build(Arc::new(Strategy));
    (Arc::new(prover), entered, gate)
}
fn budget(n: usize) -> ConcurrencyBudget {
    ConcurrencyBudget::new(NonZeroUsize::new(n).unwrap())
}
async fn until(mut f: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !f() {
            yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// Ticks `prover` until `f` holds, for work that may find no capacity at first.
async fn tick_until(prover: &Arc<Prover<Spec>>, mut f: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !f() {
            prover.tick().await;
            yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// Wraps the in-memory store with switchable failures, a scan counter and
/// key-ordered listings like the sled and MDBX stores.
#[derive(Default)]
struct FaultStore {
    inner: InMemoryTaskStore,
    fail_scan: AtomicBool,
    fail_update: AtomicBool,
    fail_deadline: AtomicBool,
    fail_clear: AtomicBool,
    fail_metadata: AtomicBool,
    fail_proving_key: Mutex<Option<Vec<u8>>>,
    write_failures: AtomicUsize,
    scans: AtomicUsize,
}
impl FaultStore {
    fn fail(&self, what: &str) -> ProverResult<()> {
        self.write_failures.fetch_add(1, Ordering::SeqCst);
        Err(ProverError::Storage(format!("{what} unavailable")))
    }
}
impl TaskStore for FaultStore {
    fn get(&self, k: &[u8]) -> ProverResult<Option<TaskRecord>> {
        self.inner.get(k)
    }
    fn insert(&self, r: TaskRecord) -> ProverResult<()> {
        self.inner.insert(r)
    }
    fn update_status(&self, k: &[u8], s: TaskStatus) -> ProverResult<()> {
        let proving_fails = matches!(s, TaskStatus::Proving { .. })
            && self.fail_proving_key.lock().as_deref() == Some(k);
        if self.fail_update.load(Ordering::SeqCst) || proving_fails {
            return self.fail("update");
        }
        self.inner.update_status(k, s)
    }
    fn set_retry_after(&self, k: &[u8], t: u64) -> ProverResult<()> {
        if self.fail_deadline.load(Ordering::SeqCst) {
            return self.fail("set_retry_after");
        }
        self.inner.set_retry_after(k, t)
    }
    fn set_metadata(&self, k: &[u8], d: Vec<u8>) -> ProverResult<()> {
        if self.fail_metadata.load(Ordering::SeqCst) {
            return self.fail("set_metadata");
        }
        self.inner.set_metadata(k, d)
    }
    fn clear_metadata(&self, k: &[u8]) -> ProverResult<()> {
        if self.fail_clear.load(Ordering::SeqCst) {
            return self.fail("clear_metadata");
        }
        self.inner.clear_metadata(k)
    }
    fn list_retriable(&self, t: u64) -> ProverResult<Vec<TaskRecord>> {
        let mut records = self.inner.list_retriable(t)?;
        records.sort_by(|a, b| a.key().cmp(b.key()));
        Ok(records)
    }
    fn list_unfinished(&self) -> ProverResult<Vec<TaskRecord>> {
        self.scans.fetch_add(1, Ordering::SeqCst);
        if self.fail_scan.load(Ordering::SeqCst) {
            return Err(ProverError::Storage("scan unavailable".into()));
        }
        let mut records = self.inner.list_unfinished()?;
        records.sort_by(|a, b| a.key().cmp(b.key()));
        Ok(records)
    }
    fn count(&self) -> ProverResult<usize> {
        self.inner.count()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_submit_and_tick_start_a_task_once() {
    let (p, entered, gate) = build(Arc::new(InMemoryTaskStore::new()), false);
    let mut calls = Vec::new();
    for _ in 0..50 {
        let p = p.clone();
        calls.push(tokio::spawn(async move {
            p.submit(Task(1)).await.unwrap();
            p.tick().await;
        }));
    }
    for call in calls {
        call.await.unwrap();
    }
    until(|| entered.load(Ordering::SeqCst) > 0).await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    gate.add_permits(1);
    until(|| matches!(p.get_status(&Task(1)).unwrap(), TaskStatus::Completed)).await;
}

#[tokio::test]
async fn tick_starts_pending_rows_left_by_an_earlier_process() {
    let store = Arc::new(InMemoryTaskStore::new());
    for t in 0..3 {
        store
            .insert(TaskRecord::new(vec![t], TaskStatus::Pending))
            .unwrap();
    }
    let (p, entered, gate) = build(store, false);
    p.tick().await;
    until(|| entered.load(Ordering::SeqCst) == 3).await;
    gate.add_permits(3);
    until(|| (0..3).all(|t| p.get_status(&Task(t)).unwrap() == TaskStatus::Completed)).await;
}

#[tokio::test]
async fn failed_recovery_blocks_submission_and_is_retried() {
    let store = Arc::new(FaultStore::default());
    store
        .insert(TaskRecord::new(
            vec![0],
            TaskStatus::Proving {
                counts: AttemptCounts::default(),
            },
        ))
        .unwrap();
    store.fail_scan.store(true, Ordering::SeqCst);
    let (p, entered, gate) = build(store.clone(), false);
    assert!(p.submit(Task(1)).await.is_err());
    assert!(!p.dispatch.lock().recovered);
    store.fail_scan.store(false, Ordering::SeqCst);
    store.fail_update.store(true, Ordering::SeqCst);
    p.tick().await;
    assert!(!p.dispatch.lock().recovered);
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    store.fail_update.store(false, Ordering::SeqCst);
    p.submit(Task(1)).await.unwrap();
    assert!(p.dispatch.lock().recovered);
    assert!(matches!(
        p.get_status(&Task(0)).unwrap(),
        TaskStatus::PermanentFailure { .. }
    ));
    gate.add_permits(1);
}

#[tokio::test]
async fn one_failing_row_does_not_stop_dispatch() {
    let store = Arc::new(FaultStore::default());
    for t in 0..3 {
        store
            .insert(TaskRecord::new(vec![t], TaskStatus::Pending))
            .unwrap();
    }
    // Row 0 comes first in key order and can never be marked `Proving`.
    *store.fail_proving_key.lock() = Some(vec![0]);
    let (p, entered, gate) = build(store.clone(), false);
    p.tick().await;
    until(|| entered.load(Ordering::SeqCst) == 2).await;
    assert_eq!(p.get_status(&Task(0)).unwrap(), TaskStatus::Pending);
    gate.add_permits(2);
}

#[tokio::test]
async fn recovery_preserves_metadata_and_all_attempt_counters() {
    let store = Arc::new(InMemoryTaskStore::new());
    let counts = AttemptCounts {
        retry: 1,
        resubmit: 2,
        recheck: 3,
    };
    store
        .insert(TaskRecord::new(vec![1], TaskStatus::Proving { counts }))
        .unwrap();
    store.set_metadata(&[1], vec![42]).unwrap();
    let (mut p, entered, gate) = build(store.clone(), false);
    Arc::get_mut(&mut p).unwrap().config.retry = Some(RetryConfig::default());
    p.tick().await;
    let record = store.get(&[1]).unwrap().unwrap();
    assert_eq!(
        record.status().counts(),
        AttemptCounts { retry: 2, ..counts }
    );
    assert_eq!(record.metadata(), Some([42].as_slice()));
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    store.set_retry_after(&[1], 0).unwrap();
    p.tick().await;
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    assert_eq!(
        p.get_status(&Task(1)).unwrap().counts(),
        AttemptCounts { retry: 2, ..counts }
    );
    gate.add_permits(1);
}

#[tokio::test]
async fn failed_completion_write_leaves_the_row_for_restart_recovery() {
    let store = Arc::new(FaultStore::default());
    let (p, entered, gate) = build(store.clone(), false);
    p.submit(Task(1)).await.unwrap();
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    store.fail_update.store(true, Ordering::SeqCst);
    gate.add_permits(1);
    until(|| store.write_failures.load(Ordering::SeqCst) > 0).await;
    store.fail_update.store(false, Ordering::SeqCst);

    // Waiters hear only recorded outcomes, and dispatch never restarts a
    // `Proving` row in the same process.
    let waited = timeout(Duration::from_millis(200), p.wait_for_tasks(&[Task(1)])).await;
    assert!(waited.is_err());
    p.tick().await;
    assert!(matches!(
        p.get_status(&Task(1)).unwrap(),
        TaskStatus::Proving { .. }
    ));
    assert_eq!(entered.load(Ordering::SeqCst), 1);

    // A restarted prover counts the attempt as interrupted.
    let (mut restarted, _, _) = build(store.clone(), false);
    Arc::get_mut(&mut restarted).unwrap().config.retry = Some(RetryConfig::default());
    restarted.tick().await;
    let status = restarted.get_status(&Task(1)).unwrap();
    assert!(matches!(status, TaskStatus::TransientFailure { .. }));
    assert_eq!(status.counts().retry, 1);
}

#[tokio::test]
async fn failed_deadline_write_leaves_a_blocked_task_proving() {
    let store = Arc::new(FaultStore::default());
    store.fail_deadline.store(true, Ordering::SeqCst);
    let (p, _, _) = build(store.clone(), true);
    p.submit(Task(1)).await.unwrap();
    until(|| store.write_failures.load(Ordering::SeqCst) > 0).await;
    let record = store.get(&[1]).unwrap().unwrap();
    assert!(matches!(record.status(), TaskStatus::Proving { .. }));
    assert_eq!(record.retry_after_secs(), None);
    assert_eq!(record.status().counts().recheck, 0);
}

struct ResubmitStrategy;
impl ProveStrategy<Spec> for ResubmitStrategy {
    fn prove(&self, _: &(), _ctx: ProveContext) -> ProverResult<ProofReceiptWithMetadata> {
        Err(ProverError::resubmit("expired remote request"))
    }
}

#[tokio::test]
async fn retry_writes_metadata_clear_and_deadline_before_status() {
    for (fail_clear, fail_deadline) in [(true, false), (false, true), (false, false)] {
        let store = Arc::new(FaultStore::default());
        store
            .insert(TaskRecord::new(vec![1], TaskStatus::Pending))
            .unwrap();
        store.set_metadata(&[1], vec![42]).unwrap();
        store.fail_clear.store(fail_clear, Ordering::SeqCst);
        store.fail_deadline.store(fail_deadline, Ordering::SeqCst);
        let (mut p, _, gate) = build(store.clone(), false);
        let inner = Arc::get_mut(&mut p).unwrap();
        inner.config.retry = Some(RetryConfig::default());
        inner.strategy = Arc::new(ResubmitStrategy);
        p.submit(Task(1)).await.unwrap();
        gate.add_permits(1);
        until(|| {
            store.write_failures.load(Ordering::SeqCst) > 0
                || !store.get(&[1]).unwrap().unwrap().status().is_in_progress()
        })
        .await;

        let record = store.get(&[1]).unwrap().unwrap();
        if fail_clear || fail_deadline {
            // The first failed write stops the sequence before the status.
            assert!(matches!(record.status(), TaskStatus::Proving { .. }));
            assert_eq!(record.status().counts().resubmit, 0);
            if fail_clear {
                assert_eq!(record.metadata(), Some([42].as_slice()));
            }
        } else {
            assert!(matches!(
                record.status(),
                TaskStatus::TransientFailure { .. }
            ));
            assert_eq!(record.status().counts().resubmit, 1);
            assert_eq!(record.metadata(), None);
            assert!(record.retry_after_secs().is_some());
        }
    }
}

/// Saves a proof ID the way the remote strategy does, then succeeds.
#[cfg(feature = "remote")]
struct SaveIdStrategy;
#[cfg(feature = "remote")]
impl ProveStrategy<Spec> for SaveIdStrategy {
    fn prove(&self, _: &(), mut ctx: ProveContext) -> ProverResult<ProofReceiptWithMetadata> {
        ctx.persist(vec![7]);
        Ok(ProofReceiptWithMetadata::default())
    }
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn failed_proof_id_write_is_logged_and_the_attempt_continues() {
    let store = Arc::new(FaultStore::default());
    store.fail_metadata.store(true, Ordering::SeqCst);
    let (mut p, _, gate) = build(store.clone(), false);
    Arc::get_mut(&mut p).unwrap().strategy = Arc::new(SaveIdStrategy);
    p.submit(Task(1)).await.unwrap();
    gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
    assert_eq!(store.write_failures.load(Ordering::SeqCst), 1);
    assert_eq!(store.get(&[1]).unwrap().unwrap().metadata(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_budget_bounds_all_provers_before_input_and_pending_drains() {
    // Four instances model chunk/account provers for two resident versions.
    let budget = budget(2);
    let provers: Vec<_> = (0..4)
        .map(|_| build_limited(budget.clone(), Arc::new(InMemoryTaskStore::new()), false))
        .collect();
    for (p, _, _) in &provers {
        for t in 0..20 {
            p.submit(Task(t)).await.unwrap();
        }
    }
    until(|| {
        provers
            .iter()
            .map(|(_, n, _)| n.load(Ordering::SeqCst))
            .sum::<usize>()
            == 2
    })
    .await;
    let pending: usize = provers
        .iter()
        .map(|(p, _, _)| {
            p.task_store
                .list_unfinished()
                .unwrap()
                .iter()
                .filter(|r| matches!(r.status(), TaskStatus::Pending))
                .count()
        })
        .sum();
    assert_eq!(pending, 78);
    for (_, _, gate) in &provers {
        gate.add_permits(20);
    }
    timeout(Duration::from_secs(5), async {
        loop {
            for (p, _, _) in &provers {
                p.tick().await;
            }
            if provers
                .iter()
                .all(|(p, _, _)| p.task_store.list_unfinished().unwrap().is_empty())
            {
                break;
            }
            yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        provers
            .iter()
            .map(|(_, n, _)| n.load(Ordering::SeqCst))
            .sum::<usize>(),
        80
    );
}

#[tokio::test]
async fn restart_pending_backlog_is_limited() {
    let store = Arc::new(InMemoryTaskStore::new());
    for t in 0..200 {
        store
            .insert(TaskRecord::new(vec![t], TaskStatus::Pending))
            .unwrap();
    }
    let (p, entered, gate) = build_limited(budget(3), store.clone(), false);
    p.tick().await;
    until(|| entered.load(Ordering::SeqCst) == 3).await;
    assert_eq!(
        store
            .list_unfinished()
            .unwrap()
            .iter()
            .filter(|r| matches!(r.status(), TaskStatus::Pending))
            .count(),
        197
    );
    gate.add_permits(3);
}

#[tokio::test]
async fn blocked_input_releases_capacity_without_spending_retry_budget() {
    let shared = budget(1);
    let (blocked, _, _) = build_limited(shared.clone(), Arc::new(InMemoryTaskStore::new()), true);
    blocked.submit(Task(1)).await.unwrap();
    until(|| {
        matches!(
            blocked.get_status(&Task(1)).unwrap(),
            TaskStatus::Blocked { .. }
        )
    })
    .await;
    assert_eq!(blocked.get_status(&Task(1)).unwrap().counts().retry, 0);
    let (ready, entered, gate) = build_limited(shared, Arc::new(InMemoryTaskStore::new()), false);
    ready.submit(Task(2)).await.unwrap();
    tick_until(&ready, || entered.load(Ordering::SeqCst) == 1).await;
    gate.add_permits(1);
}

#[tokio::test]
async fn dispatch_skips_store_scans_while_capacity_is_exhausted() {
    let store = Arc::new(FaultStore::default());
    let (p, entered, gate) = build_limited(budget(1), store.clone(), false);
    p.submit(Task(1)).await.unwrap();
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    let scans = store.scans.load(Ordering::SeqCst);
    p.tick().await;
    assert_eq!(store.scans.load(Ordering::SeqCst), scans);
    gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
    p.tick().await;
    assert_eq!(store.scans.load(Ordering::SeqCst), scans + 1);
}

struct Hook(Arc<Semaphore>, Arc<AtomicBool>);
#[async_trait]
impl ReceiptHook<Spec> for Hook {
    async fn on_receipt(&self, _: &Task, _: &ProofReceiptWithMetadata) -> ProverResult<()> {
        self.1.store(true, Ordering::SeqCst);
        self.0.acquire().await.unwrap().forget();
        Ok(())
    }
}

#[tokio::test]
async fn receipt_hook_runs_without_submission_capacity() {
    let shared = budget(1);
    let (mut p, entered, gate) =
        build_limited(shared.clone(), Arc::new(InMemoryTaskStore::new()), false);
    let hook_gate = Arc::new(Semaphore::new(0));
    let hook_entered = Arc::new(AtomicBool::new(false));
    Arc::get_mut(&mut p).unwrap().receipt_hook =
        Some(Arc::new(Hook(hook_gate.clone(), hook_entered.clone())));
    p.submit(Task(1)).await.unwrap();
    gate.add_permits(1);
    until(|| hook_entered.load(Ordering::SeqCst)).await;

    // The hook holds no capacity, so another prover's task starts meanwhile.
    let (other, other_entered, other_gate) =
        build_limited(shared, Arc::new(InMemoryTaskStore::new()), false);
    other.submit(Task(2)).await.unwrap();
    tick_until(&other, || other_entered.load(Ordering::SeqCst) == 1).await;

    // The task is still `Proving`, so a tick does not start it again.
    p.tick().await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    hook_gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
    other_gate.add_permits(1);
}

#[tokio::test]
async fn checkpointed_receipt_skips_preparation_and_releases_capacity_before_hook() {
    let shared = budget(1);
    let (mut p, inputs, _) =
        build_limited(shared.clone(), Arc::new(InMemoryTaskStore::new()), false);
    let receipts = InMemoryReceiptStore::new();
    receipts
        .put(&[1], &ProofReceiptWithMetadata::default())
        .unwrap();
    let hook_gate = Arc::new(Semaphore::new(0));
    let hook_entered = Arc::new(AtomicBool::new(false));
    let inner = Arc::get_mut(&mut p).unwrap();
    inner.receipt_store = Some(Arc::new(receipts));
    inner.receipt_hook = Some(Arc::new(Hook(hook_gate.clone(), hook_entered.clone())));
    p.submit(Task(1)).await.unwrap();
    until(|| hook_entered.load(Ordering::SeqCst)).await;
    assert_eq!(inputs.load(Ordering::SeqCst), 0);
    assert!(shared.try_acquire().is_some());
    hook_gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_the_async_attempt_keeps_capacity_until_the_blocking_proof_exits() {
    let shared = budget(1);
    let store = Arc::new(InMemoryTaskStore::new());
    let (mut p, _, input_gate) = build_limited(shared.clone(), store.clone(), false);
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new((Mutex::new(false), parking_lot::Condvar::new()));
    let native_entered = entered.clone();
    let native_release = release.clone();
    let host = NativeHost::new_with_random_key(move |_| {
        let (lock, notify) = native_release.as_ref();
        let mut released = lock.lock();
        native_entered.store(true, Ordering::SeqCst);
        while !*released {
            notify.wait(&mut released);
        }
    });
    Arc::get_mut(&mut p).unwrap().strategy = Arc::new(NativeStrategy::new(host));
    let key = vec![1];
    store
        .insert(TaskRecord::new(key.clone(), TaskStatus::Pending))
        .unwrap();
    let record = store.get(&key).unwrap().unwrap();
    let permit = shared.try_acquire();
    let runner = p.clone();
    let task = tokio::spawn(async move {
        runner.run_task(Task(1), key, record, permit).await;
    });
    input_gate.add_permits(1);
    until(|| entered.load(Ordering::SeqCst)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let still_limited = shared.try_acquire().is_none();
    *release.0.lock() = true;
    release.1.notify_all();
    assert!(
        still_limited,
        "cancelled async owner freed a still-running proof's capacity"
    );
    until(|| shared.try_acquire().is_some()).await;
}

/// Panics while resolving input, as a bug in a consumer's spec would.
struct PanicSpec;
#[async_trait]
impl ProofSpec for PanicSpec {
    type Task = Task;
    type Program = Program;
    async fn resolve_input(&self, _: &Task) -> ProverResult<InputResolution<()>> {
        panic!("bug in input assembly");
    }
}
impl ProveStrategy<PanicSpec> for Strategy {
    fn prove(&self, _: &(), _ctx: ProveContext) -> ProverResult<ProofReceiptWithMetadata> {
        Ok(ProofReceiptWithMetadata::default())
    }
}
fn panicking_prover(store: Arc<InMemoryTaskStore>, retry: RetryConfig) -> Arc<Prover<PanicSpec>> {
    Arc::new(
        ProverBuilder::new(PanicSpec)
            .task_store(store)
            .retry(retry)
            .build(Arc::new(Strategy)),
    )
}

#[tokio::test]
async fn panicked_attempt_retries_like_a_crash() {
    let store = Arc::new(InMemoryTaskStore::new());
    let p = panicking_prover(store.clone(), RetryConfig::default());
    p.submit(Task(1)).await.unwrap();
    until(|| !p.get_status(&Task(1)).unwrap().is_in_progress()).await;
    let status = p.get_status(&Task(1)).unwrap();
    assert!(matches!(status, TaskStatus::TransientFailure { .. }));
    assert_eq!(status.counts().retry, 1);
    // A retry is not terminal, so waiters keep waiting.
    let waited = timeout(Duration::from_millis(200), p.wait_for_tasks(&[Task(1)])).await;
    assert!(waited.is_err());

    // The task stays dispatchable: once due, it runs (and panics) again.
    store.set_retry_after(&[1], 0).unwrap();
    p.tick().await;
    until(|| p.get_status(&Task(1)).unwrap().counts().retry == 2).await;
}

#[tokio::test]
async fn panicking_task_fails_once_its_retry_budget_is_spent() {
    let store = Arc::new(InMemoryTaskStore::new());
    let retry = RetryConfig {
        max_retries: 1,
        ..RetryConfig::default()
    };
    let p = panicking_prover(store, retry);
    p.submit(Task(1)).await.unwrap();
    let results = timeout(Duration::from_secs(5), p.wait_for_tasks(&[Task(1)]))
        .await
        .unwrap()
        .unwrap();
    assert!(results[0].is_failed());
    assert!(matches!(
        p.get_status(&Task(1)).unwrap(),
        TaskStatus::PermanentFailure { .. }
    ));
}

fn permanent_failure(error: &str) -> TaskStatus {
    TaskStatus::PermanentFailure {
        error: error.into(),
    }
}

#[tokio::test]
async fn reset_permanent_failure_restarts_the_task() {
    let store = Arc::new(InMemoryTaskStore::new());
    store
        .insert(TaskRecord::new(vec![1], permanent_failure("bad witness")))
        .unwrap();
    let (p, entered, gate) = build_limited(budget(1), store, false);
    assert_eq!(
        p.reset_permanent_failure(Task(1)).await.unwrap(),
        ResetOutcome::Reset {
            cleared_error: "bad witness".into()
        }
    );
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
}

#[tokio::test]
async fn reset_permanent_failure_refuses_other_rows() {
    let store = Arc::new(InMemoryTaskStore::new());
    store
        .insert(TaskRecord::new(vec![1], TaskStatus::Completed))
        .unwrap();
    let (p, entered, _) = build_limited(budget(1), store, false);
    assert_eq!(
        p.reset_permanent_failure(Task(1)).await.unwrap(),
        ResetOutcome::NotPermanentlyFailed(TaskStatus::Completed)
    );
    assert_eq!(p.get_status(&Task(1)).unwrap(), TaskStatus::Completed);
    assert_eq!(
        p.reset_permanent_failure(Task(2)).await.unwrap(),
        ResetOutcome::NotFound
    );
    assert_eq!(entered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reset_permanent_failure_refuses_a_task_in_flight() {
    let store = Arc::new(InMemoryTaskStore::new());
    let (p, entered, gate) = build_limited(budget(1), store, false);
    p.submit(Task(1)).await.unwrap();
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    // A healthy attempt in flight is not a failure.
    assert!(matches!(
        p.reset_permanent_failure(Task(1)).await.unwrap(),
        ResetOutcome::NotPermanentlyFailed(TaskStatus::Proving { .. })
    ));
    gate.add_permits(1);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reset_permanent_failure_without_capacity_stays_pending_until_tick() {
    let store = Arc::new(InMemoryTaskStore::new());
    store
        .insert(TaskRecord::new(
            vec![2],
            permanent_failure("retries exhausted"),
        ))
        .unwrap();
    let (p, entered, gate) = build_limited(budget(1), store, false);
    p.submit(Task(1)).await.unwrap();
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    assert!(matches!(
        p.reset_permanent_failure(Task(2)).await.unwrap(),
        ResetOutcome::Reset { .. }
    ));
    assert_eq!(p.get_status(&Task(2)).unwrap(), TaskStatus::Pending);
    gate.add_permits(2);
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
    tick_until(&p, || {
        p.get_status(&Task(2)).unwrap() == TaskStatus::Completed
    })
    .await;
    assert_eq!(entered.load(Ordering::SeqCst), 2);
}

/// Fails its first input resolution permanently, then succeeds.
struct FailOnceSpec {
    calls: AtomicUsize,
}
#[async_trait]
impl ProofSpec for FailOnceSpec {
    type Task = Task;
    type Program = Program;
    async fn resolve_input(&self, _: &Task) -> ProverResult<InputResolution<()>> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ProverError::permanent("bad witness"));
        }
        Ok(InputResolution::Ready(()))
    }
}
impl ProveStrategy<FailOnceSpec> for Strategy {
    fn prove(&self, _: &(), _ctx: ProveContext) -> ProverResult<ProofReceiptWithMetadata> {
        Ok(ProofReceiptWithMetadata::default())
    }
}

/// Holds an attempt between its `PermanentFailure` write and its exit.
///
/// After the write commits, the store either pauses the writer, or panics and
/// then pauses the next read, which is the panic handler's. A paused call sets
/// `reached` and blocks its worker thread until `release` is set.
#[derive(Default)]
struct TerminalHookStore {
    inner: InMemoryTaskStore,
    pause_after_failure: AtomicBool,
    panic_after_failure: AtomicBool,
    pause_next_get: AtomicBool,
    reached: AtomicBool,
    release: AtomicBool,
}
impl TerminalHookStore {
    fn pause(&self) {
        self.reached.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1));
        }
    }
}
impl TaskStore for TerminalHookStore {
    fn get(&self, k: &[u8]) -> ProverResult<Option<TaskRecord>> {
        if self.pause_next_get.swap(false, Ordering::SeqCst) {
            self.pause();
        }
        self.inner.get(k)
    }
    fn insert(&self, r: TaskRecord) -> ProverResult<()> {
        self.inner.insert(r)
    }
    fn update_status(&self, k: &[u8], s: TaskStatus) -> ProverResult<()> {
        let failure = matches!(s, TaskStatus::PermanentFailure { .. });
        self.inner.update_status(k, s)?;
        if failure && self.pause_after_failure.swap(false, Ordering::SeqCst) {
            self.pause();
        }
        if failure && self.panic_after_failure.swap(false, Ordering::SeqCst) {
            self.pause_next_get.store(true, Ordering::SeqCst);
            panic!("store bug after committing the failure");
        }
        Ok(())
    }
    fn set_retry_after(&self, k: &[u8], t: u64) -> ProverResult<()> {
        self.inner.set_retry_after(k, t)
    }
    fn set_metadata(&self, k: &[u8], d: Vec<u8>) -> ProverResult<()> {
        self.inner.set_metadata(k, d)
    }
    fn clear_metadata(&self, k: &[u8]) -> ProverResult<()> {
        self.inner.clear_metadata(k)
    }
    fn list_retriable(&self, t: u64) -> ProverResult<Vec<TaskRecord>> {
        self.inner.list_retriable(t)
    }
    fn list_unfinished(&self) -> ProverResult<Vec<TaskRecord>> {
        self.inner.list_unfinished()
    }
    fn count(&self) -> ProverResult<usize> {
        self.inner.count()
    }
}

fn fail_once_prover(store: Arc<TerminalHookStore>) -> Arc<Prover<FailOnceSpec>> {
    let spec = FailOnceSpec {
        calls: AtomicUsize::new(0),
    };
    Arc::new(
        ProverBuilder::new(spec)
            .task_store(store)
            .build(Arc::new(Strategy)),
    )
}

/// Resets `task` once its failed attempt has exited.
async fn reset_when_attempt_exits(p: &Arc<Prover<FailOnceSpec>>, task: u8) -> ResetOutcome {
    timeout(Duration::from_secs(5), async {
        loop {
            match p.reset_permanent_failure(Task(task)).await.unwrap() {
                ResetOutcome::AttemptStillRunning => yield_now().await,
                outcome => return outcome,
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_waits_until_the_failed_attempt_has_notified_waiters() {
    let store = Arc::new(TerminalHookStore::default());
    store.pause_after_failure.store(true, Ordering::SeqCst);
    let p = fail_once_prover(store.clone());
    p.submit(Task(1)).await.unwrap();
    until(|| store.reached.load(Ordering::SeqCst)).await;
    // The row reads PermanentFailure, but its attempt has not notified waiters
    // yet. A reset now would let that failure reach the restarted task's waiters.
    let early = p.reset_permanent_failure(Task(1)).await.unwrap();
    store.release.store(true, Ordering::SeqCst);
    assert_eq!(early, ResetOutcome::AttemptStillRunning);
    assert!(matches!(
        reset_when_attempt_exits(&p, 1).await,
        ResetOutcome::Reset { .. }
    ));
    let results = timeout(Duration::from_secs(5), p.wait_for_tasks(&[Task(1)]))
        .await
        .unwrap()
        .unwrap();
    assert!(results[0].is_completed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_waits_until_a_panicked_attempt_is_settled() {
    let store = Arc::new(TerminalHookStore::default());
    store.panic_after_failure.store(true, Ordering::SeqCst);
    let p = fail_once_prover(store.clone());
    p.submit(Task(1)).await.unwrap();
    // The attempt panicked after its failure committed; its panic handler is
    // paused before it reads the row. The restarted attempt would carry the
    // same `Proving` counters, so the handler would mistake it for its own.
    until(|| store.reached.load(Ordering::SeqCst)).await;
    let early = p.reset_permanent_failure(Task(1)).await.unwrap();
    store.release.store(true, Ordering::SeqCst);
    assert_eq!(early, ResetOutcome::AttemptStillRunning);
    assert!(matches!(
        reset_when_attempt_exits(&p, 1).await,
        ResetOutcome::Reset { .. }
    ));
    until(|| p.get_status(&Task(1)).unwrap() == TaskStatus::Completed).await;
}

#[cfg(feature = "remote")]
mod remote {
    use serde::{de::DeserializeOwned, Serialize};
    use zkaleido::{
        ExecutionSummary, ProgramId, RemoteProofStatus, VerifyingKey, ZkVm, ZkVmExecutor,
        ZkVmOutputExtractor, ZkVmProver, ZkVmRemoteProver, ZkVmTypedVerifier, ZkVmVkProvider,
    };

    use super::*;

    type HostInput<'a> = <<NativeHost as ZkVmExecutor>::Input<'a> as ZkVmInputBuilder<'a>>::Input;
    type HostReceipt = <NativeHost as ZkVmProver>::ZkVmProofReceipt;

    /// Keeps the real `RemoteStrategy` polling until the test finishes it.
    #[derive(Clone, Debug)]
    struct Host {
        native: NativeHost,
        budget: ConcurrencyBudget,
        submissions: Arc<AtomicUsize>,
        polls: Arc<AtomicUsize>,
        finish: Arc<Semaphore>,
    }
    impl ZkVmExecutor for Host {
        type Input<'a> = <NativeHost as ZkVmExecutor>::Input<'a>;
        fn execute<'a>(&self, input: HostInput<'a>) -> ZkVmResult<ExecutionSummary> {
            self.native.execute(input)
        }
        fn get_elf(&self) -> &[u8] {
            self.native.get_elf()
        }
        fn program_id(&self) -> ProgramId {
            self.native.program_id()
        }
        fn save_trace(&self, name: &str) {
            self.native.save_trace(name);
        }
    }
    impl ZkVmProver for Host {
        type ZkVmProofReceipt = HostReceipt;
        fn prove_inner<'a>(
            &self,
            input: HostInput<'a>,
            kind: ProofType,
        ) -> ZkVmResult<HostReceipt> {
            self.native.prove_inner(input, kind)
        }
    }
    impl ZkVmTypedVerifier for Host {
        type ZkVmProofReceipt = HostReceipt;
        fn verify_inner(&self, receipt: &HostReceipt) -> ZkVmResult<()> {
            self.native.verify_inner(receipt)
        }
    }
    impl ZkVmOutputExtractor for Host {
        fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
            values: &PublicValues,
        ) -> ZkVmResult<T> {
            NativeHost::extract_serde_public_output(values)
        }
    }
    impl ZkVmVkProvider for Host {
        fn vk(&self) -> VerifyingKey {
            self.native.vk()
        }
    }
    impl ZkVmHost for Host {
        fn zkvm(&self) -> ZkVm {
            self.native.zkvm()
        }
    }
    #[async_trait]
    impl ZkVmRemoteProver for Host {
        type ProofId = Task;
        async fn start_proving<'a>(&self, _: HostInput<'a>, _: ProofType) -> ZkVmResult<Task> {
            assert!(
                self.budget.try_acquire().is_none(),
                "submission must own capacity"
            );
            self.submissions.fetch_add(1, Ordering::SeqCst);
            Ok(Task(7))
        }
        async fn get_status(&self, _: &Task) -> ZkVmResult<RemoteProofStatus> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            self.finish.acquire().await.unwrap().forget();
            Ok(RemoteProofStatus::Completed)
        }
        async fn get_proof(&self, _: &Task) -> ZkVmResult<ProofReceiptWithMetadata> {
            Ok(ProofReceiptWithMetadata::default())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_capacity_is_released_after_submission_or_a_valid_saved_id() {
        // A valid saved ID resumes without input; malformed metadata submits a
        // replacement.
        for saved in [None, Some(vec![7]), Some(Vec::new())] {
            let resumed = saved.as_ref().is_some_and(|bytes| bytes.len() == 1);
            let shared = budget(1);
            let store = Arc::new(InMemoryTaskStore::new());
            store
                .insert(TaskRecord::new(vec![1], TaskStatus::Pending))
                .unwrap();
            if let Some(bytes) = saved {
                store.set_metadata(&[1], bytes).unwrap();
            }
            let host = Host {
                native: NativeHost::new_with_random_key(|_| {}),
                budget: shared.clone(),
                submissions: Arc::new(AtomicUsize::new(0)),
                polls: Arc::new(AtomicUsize::new(0)),
                finish: Arc::new(Semaphore::new(0)),
            };
            let (spec, entered, gate) = spec(false);
            gate.add_permits(2);
            let p = Arc::new(
                ProverBuilder::new(spec)
                    .task_store(store.clone())
                    .concurrency_budget(shared.clone())
                    .remote_with_interval(host.clone(), Duration::from_millis(1)),
            );
            p.submit(Task(1)).await.unwrap();
            until(|| host.polls.load(Ordering::SeqCst) == 1).await;

            // Polling holds no capacity, and the proof ID is saved before it.
            assert!(shared.try_acquire().is_some());
            assert_eq!(
                store.get(&[1]).unwrap().unwrap().metadata(),
                Some([7].as_slice())
            );

            // The polling task is `Proving`: a resubmit or tick leaves it alone,
            // while a different task can submit. A resumed proof is polled
            // without preparing input.
            p.submit(Task(1)).await.unwrap();
            p.tick().await;
            assert_eq!(entered.load(Ordering::SeqCst), usize::from(!resumed));
            p.submit(Task(2)).await.unwrap();
            until(|| host.polls.load(Ordering::SeqCst) == 2).await;
            assert_eq!(
                host.submissions.load(Ordering::SeqCst),
                if resumed { 1 } else { 2 }
            );
            host.finish.add_permits(2);
            until(|| {
                p.get_status(&Task(1)).unwrap() == TaskStatus::Completed
                    && p.get_status(&Task(2)).unwrap() == TaskStatus::Completed
            })
            .await;
        }
    }
}

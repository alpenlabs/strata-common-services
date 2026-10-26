use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::{sync::Semaphore, task::yield_now, time::timeout};
use zkaleido::{
    ProofReceiptWithMetadata, ProofType, PublicValues, ZkVmInputBuilder, ZkVmInputResult,
    ZkVmProgram, ZkVmResult,
};

use super::*;

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
async fn until(mut f: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !f() {
            yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// Wraps the in-memory store with switchable failures and key-ordered
/// listings like the sled and MDBX stores.
#[derive(Default)]
struct FaultStore {
    inner: InMemoryTaskStore,
    fail_scan: AtomicBool,
    fail_proving_key: Mutex<Option<Vec<u8>>>,
    write_failures: AtomicUsize,
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
        if proving_fails {
            return self.fail("update");
        }
        self.inner.update_status(k, s)
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
        let mut records = self.inner.list_retriable(t)?;
        records.sort_by(|a, b| a.key().cmp(b.key()));
        Ok(records)
    }
    fn list_unfinished(&self) -> ProverResult<Vec<TaskRecord>> {
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
    p.tick().await;
    assert!(!p.dispatch.lock().recovered);
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    store.fail_scan.store(false, Ordering::SeqCst);
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

/**
 * @id run422/resolved-calls-from-testfile
 * @kind table
 */
import rust
from File tf, int resolvedCalls, int distinctTargets
where
  tf.getAbsolutePath().matches("%run_422_d7d14_safety_record_store_tests.rs") and
  resolvedCalls =
    count(Call c |
      c.getFile() = tf and
      c.getStaticTarget().getFile().getAbsolutePath().matches("%/safety_record_store/%.rs")
    ) and
  distinctTargets =
    count(Function target |
      target.getFile().getAbsolutePath().matches("%/safety_record_store/%.rs") and
      exists(Call c | c.getFile() = tf and c.getStaticTarget() = target)
    )
select tf.getAbsolutePath() as testfile, resolvedCalls, distinctTargets

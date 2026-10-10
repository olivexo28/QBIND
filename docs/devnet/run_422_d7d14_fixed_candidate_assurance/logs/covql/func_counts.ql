/**
 * @id run422/func-counts
 * @kind table
 */
import rust
from File f, int n
where
  (
    f.getAbsolutePath().matches("%/safety_record_store/%.rs") or
    f.getAbsolutePath().matches("%run_422_d7d14_safety_record_store_tests.rs")
  ) and
  n = count(Function fn | fn.getFile() = f)
select f.getAbsolutePath() as path, n order by path
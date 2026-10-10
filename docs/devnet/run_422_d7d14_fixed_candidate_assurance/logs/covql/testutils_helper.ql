/**
 * @id run422/testutils-helper-presence
 * @kind table
 */
import rust
from string name, int defs
where
  name = "set_inject_write_failure" and
  defs = count(Function fn | fn.getName().getText() = name)
select name, defs
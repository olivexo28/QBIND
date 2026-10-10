/**
 * @name Ill-formed type mention (individual results)
 * @description Individual source locations for rust/diagnostics/type-inference-consistency
 *              "Ill-formed type mention" inconsistencies, from the same pinned library.
 * @kind problem
 * @problem.severity error
 * @id run422/type-inference-consistency-illformed
 */
import rust
import codeql.rust.internal.typeinference.TypeInferenceConsistency as Consistency
from AstNode tm
where Consistency::illFormedTypeMention(tm)
select tm,
  "Ill-formed type mention at " + tm.getLocation().getFile().getAbsolutePath() + ":" +
    tm.getLocation().getStartLine().toString()
/**
 * @name Non-unique certain type information (individual results)
 * @kind problem
 * @problem.severity warning
 * @id run422/type-inference-consistency-nonunique
 */
import rust
import codeql.rust.internal.typeinference.TypeInferenceConsistency as Consistency
from AstNode n
where Consistency::nonUniqueCertainType(n, _)
select n, "Non-unique certain type at " + n.getLocation().getFile().getAbsolutePath() + ":" + n.getLocation().getStartLine().toString()
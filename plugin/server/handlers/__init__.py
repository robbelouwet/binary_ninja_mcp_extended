"""HTTP route handlers, grouped by domain.

Importing this package registers every route with the router registry.
"""

from . import (
    binaries,
    comments,
    data,
    debugger,
    functions,
    types,
    values,
    variables,
    xrefs,
)

from .sql_injection import SQL_INJECTION_RULES
from .hardcoded_secrets import HARDCODED_SECRETS_RULES
from .dangerous_functions import DANGEROUS_FUNCTIONS_RULES
from .unsafe_deserialization import UNSAFE_DESERIALIZATION_RULES
from .path_traversal import PATH_TRAVERSAL_RULES

ALL_RULES = (
    SQL_INJECTION_RULES
    + HARDCODED_SECRETS_RULES
    + DANGEROUS_FUNCTIONS_RULES
    + UNSAFE_DESERIALIZATION_RULES
    + PATH_TRAVERSAL_RULES
)

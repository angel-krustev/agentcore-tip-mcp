"""Setup script for Cython compilation and distribution of AgentCore-TIP-MCP-Broker.

This script compiles core modules to native extensions (.so/.pyd) and
packages them into a wheel for distribution.
"""

import os
import sys
from setuptools import setup, find_packages, Extension
from Cython.Build import cythonize

# Check if we should compile with Cython or use precompiled extensions
COMPILE_CYTHON = os.environ.get("AGENTCORE_TIP_COMPILE_CYTHON", "1") == "1"

# Core TIP modules to compile with Cython
# The .py source files for these modules will be EXCLUDED from the wheel
CYTHON_MODULES = [
    # Strategies
    "agentcore_tip.core.strategies.sso_oidc",
    "agentcore_tip.core.strategies.web_identity",
    "agentcore_tip.core.strategies.base",
    # Core modules
    "agentcore_tip.core.context",
    "agentcore_tip.core.session_store",
    "agentcore_tip.core.sql_guard",
    "agentcore_tip.core.credentials",
    "agentcore_tip.core.hooks",
    "agentcore_tip.core.config",
    "agentcore_tip.core.exceptions",
    "agentcore_tip.core.decorators",
    "agentcore_tip.core.middleware",
    "agentcore_tip.core.agent_validator",
    "agentcore_tip.core.agentcore_provider",
    # NOTE: pep_server, plane_a_ingest and plane_b_mcp are NOT compiled --
    # FastAPI needs inspect.signature() on routes
    # Integrations
    "agentcore_tip.integrations.s3_access_grants",
    "agentcore_tip.integrations.lake_formation",
    # NOTE: agentcore_tip.server is NOT compiled either -- it defines FastAPI routes
]

# Build list of .py files to exclude (compiled modules)
# NOTE: exclude_package_data doesn't work for .py files (setuptools includes them anyway)
# IP protection is handled via post-build wheel cleanup in build.sh
EXCLUDE_PY_FILES = []
for module in CYTHON_MODULES:
    py_file = module.replace(".", "/") + ".py"
    EXCLUDE_PY_FILES.append(py_file)

# Convert dotted module names to file paths
def module_to_path(module_name):
    return module_name.replace(".", "/") + ".py"

# Create Extension objects for each module
extensions = [
    Extension(
        name=module,
        sources=[module_to_path(module)],
    )
    for module in CYTHON_MODULES
]

# Common package data
package_data = {
    "agentcore_tip": ["py.typed"],
}

setup(
    name="agentcore-tip-mcp",
    version="0.1.0",
    description="Zero-trust MCP broker for AWS Trusted Identity Propagation",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Angel Krustev / VerticalTurn Inc.",
    license="Apache-2.0",
    python_requires=">=3.10",
    packages=find_packages(include=["agentcore_tip", "agentcore_tip.*"]),
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "binding": False,
            "embedsignature": False,
        },
        force=os.environ.get("AGENTCORE_TIP_FORCE_RECOMPILE", "0") == "1",
    ) if COMPILE_CYTHON else extensions,
    package_data=package_data,
    # NOTE: IP protection (removing .py source files for compiled modules)
    # is handled via post-build wheel cleanup in build.sh
    # setuptools always includes .py files by default, so exclude_package_data won't work
    entry_points={
        "console_scripts": [
            "agentcore-tip-mcp=agentcore_tip.core.pep_server:main",
        ],
    },
    install_requires=[
        "boto3>=1.35.0",
        "botocore>=1.35.0",
        "pyjwt>=2.8.0",
        "cryptography>=42.0.0",
        "pydantic>=2.7.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
        "slowapi>=0.1.9",
        "sqlglot==30.22.0",
        "redis>=5.0.1",
    ],
    zip_safe=False,
)

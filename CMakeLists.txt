cmake_minimum_required(VERSION 3.20)

# open-everything is pure Python — nothing is compiled. This file is a thin
# wrapper so the repo can also be set up via CMake:
#
#   cmake -S . -B build
#   cmake --build build --target setup        # == ./setup.sh
#   cmake --build build --target check|pytest|doctor|smoke
#
# `make setup` or `./setup.sh` do the same thing without CMake.
project(open-everything NONE)

set(OE_PY  "${CMAKE_SOURCE_DIR}/.venv/bin/python")
set(OE_BIN "${CMAKE_SOURCE_DIR}/.venv/bin/oe")

add_custom_target(setup
    COMMAND "${CMAKE_SOURCE_DIR}/setup.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "setup.sh: venv + Python deps + JDK + Ghidra")

add_custom_target(setup-model
    COMMAND "${CMAKE_SOURCE_DIR}/setup.sh" --with-model
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "setup.sh --with-model (also fetches the ~3 GB embed model)")

add_custom_target(check
    COMMAND "${CMAKE_SOURCE_DIR}/setup.sh" --check
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "verify the environment without installing")

add_custom_target(pytest
    COMMAND "${OE_PY}" -m pytest tests/ -q
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "unit tests (no Ghidra/model needed)")

add_custom_target(doctor
    COMMAND "${OE_BIN}" doctor
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "oe doctor — environment report")

add_custom_target(smoke
    COMMAND "${OE_BIN}" ingest /bin/ls
    COMMAND "${OE_BIN}" search "print file size" -k 5
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
    COMMENT "ingest /bin/ls + a search (downloads the model on first run)")

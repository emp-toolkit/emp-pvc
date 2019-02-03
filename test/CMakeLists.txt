file(GLOB FILES RELATIVE "${CMAKE_SOURCE_DIR}/test" "test_*.cpp")
set(RUNLIB ${EMP-TOOL_LIBRARIES} emp-pvc ${RELIC_LIBRARIES} gmp ssl crypto)

foreach(TEST_FILE ${FILES})
    add_executable(${TEST_FILE}_exe ${TEST_FILE})
    target_link_libraries(${TEST_FILE}_exe ${RUNLIB})
    add_test(${TEST_FILE} ${TEST_FILE}_exe)
endforeach(TEST_FILE)

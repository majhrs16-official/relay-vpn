cmake_minimum_required(VERSION 3.22.1)
project(vpncrypto C)

add_library(vpncrypto SHARED vpncrypto.c)

find_library(log-lib log)
target_link_libraries(vpncrypto ${log-lib} dl)

# Nada de excepciones C++ ni RTTI: la librería es C puro.
set_target_properties(vpncrypto PROPERTIES C_STANDARD 11)

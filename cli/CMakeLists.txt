cmake_minimum_required(VERSION 3.15)

project(cli VERSION 1.0 LANGUAGES C)

add_executable(cli
	src/cli.c
	src/crc.c
)

install(TARGETS cli DESTINATION bin)

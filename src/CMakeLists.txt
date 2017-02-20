file( GLOB CSources *.c )
add_library( p2p ${CSources} )
install( TARGETS p2p DESTINATION lib )

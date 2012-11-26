COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto

all: ssl_server.cpp ssl_client.cpp
	$(COMPILER) $(FLAGS) -o server ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o client ssl_client.cpp $(LIBRARIES)

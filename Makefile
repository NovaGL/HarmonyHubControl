# build helloworld executable when user executes "make" 

HarmonyHubControl : HarmonyHubControl.o
	$(CC) $(LDFLAGS) HarmonyHubControl.o csocket.o -o HarmonyHubControl -lstdc++

HarmonyHubControl.o: HarmonyHubControl.cpp 
	$(CC) $(CFLAGS) -c HarmonyHubControl.cpp csocket.cpp -lstdc++ 

# remove object files and executable when user executes "make clean"
clean:
	rm *.o HarmonyHubControl 

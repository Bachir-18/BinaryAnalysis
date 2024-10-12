all:
	gcc -o ../executable isos_inject.c -lbfd -ldl
	nasm -f bin  injected.asm -o ../injected.bin
clean:
	rm -f ../executable
	rm -f ../injected.bin

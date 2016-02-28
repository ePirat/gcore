all: gcore

gcore: gcore.c
	gcc -O2 -arch x86_64 -arch i386 -Wall -o $@ $<

gcore64: gcore.c
	gcc -O2 -arch x86_64 -Wall -o $@ $<

gcore32: gcore.c
	gcc -O2 -arch i386 -Wall -o $@ $<


gcore-ppc: gcore.c
	gcc -O2 -arch ppc -arch ppc64 -Wall -o $@ $<

gcore-ppc32: gcore.c
	gcc -O2 -arch ppc -Wall -o $@ $<

gcore-ppc64: gcore.c
	gcc -O2 -arch ppc64 -Wall -o $@ $<

clean:
	rm -f gcore gcore64 gcore32 gcore-ppc gcore-ppc32 gcore-ppc64

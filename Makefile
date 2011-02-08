VERS = 2.1.10
RADIUSDIR = /home/wfelipe/opt/freeradius-2.1.10
CFLAGS = -DNDEBUG -Wall -I/usr/include \
	-I$(RADIUSDIR)/include -Wall
LIBS = -lc -lssl

all: rlm_two_factor.o hotp.o rlm_two_factor-$(VERS).so test.o test hotp-sync

.c.o:
	$(CC) -g -fPIC -DPIC $(CFLAGS) -c $<

test: test.o hotp.o
	cc -g -fPIC -DPIC -o test test.o hotp.o $(LIBS)
hotp-sync: hotp-sync.o hotp.o
	cc -g -fPIC -DPIC -o hotp-sync hotp-sync.o hotp.o $(LIBS)
rlm_two_factor-$(VERS).so: rlm_two_factor.o hotp.o
	cc -g -shared -Wl,-soname,rlm_two_factor-$(VERS).so \
		-o rlm_two_factor-$(VERS).so rlm_two_factor.o hotp.o $(LIBS)
install: all
	install rlm_two_factor-$(VERS).so $(RADIUSDIR)/lib
	ln -fs rlm_two_factor-$(VERS).so $(RADIUSDIR)/lib/rlm_two_factor.so
	install -m 0644 raddb/modules/two_factor $(RADIUSDIR)/etc/raddb/modules/two_factor
clean:
	rm -f *o test hotp-sync

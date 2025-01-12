TARGET=byte-order-final
CXXFLAGS=-g

all: $(TARGET)

$(TARGET): add-nbo.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

add-nbo.o: add-nbo.cpp
	$(CXX) $(CXXFLAGS) -c add-nbo.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

NAME=fake-bpfdoor.x86

all: $(NAME)

$(NAME): fake-bpfdoor.c
	gcc -o $(NAME) fake-bpfdoor.c

clean:
	rm -f $(NAME)

re: clean all

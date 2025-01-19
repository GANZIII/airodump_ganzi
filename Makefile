# 컴파일러 설정
CC = gcc

# 컴파일 옵션
CFLAGS = -Wall -Wextra -O2

# 라이브러리 링크
LIBS = -lpcap

# 대상 파일
TARGET = airodump
SRC = airodump.c

# 기본 목표
all: $(TARGET)

# 실행 파일 생성
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# 정리
clean:
	rm -f $(TARGET)


CC      := g++

CXXFLAGS := -pedantic-errors -Wall -Wextra -Werror
CPPFLAGS := 

LFLAGS  :=

APP_NAME := main.exe
DEBUG_APP_NAME := debug.exe


DEB_DIR	 := ./build/debug
OBJ_DIR  := ./build/objects
APP_DIR  := ./build/executable
SRC_DIR  := ./src

SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
DEB_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(DEB_DIR)/%.o,$(SRC_FILES))
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))

all: $(APP_DIR)/$(APP_NAME)

debug: $(DEB_FILES)
	$(CC) $(LFLAGS) $(DEB_FILES) -o $(APP_DIR)/$(DEBUG_APP_NAME)

$(DEB_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -DDEBUG -g3 -ggdb -c -o $@ $<


$(APP_DIR)/$(APP_NAME): $(OBJ_FILES)
	$(CC) $(LFLAGS) $(OBJ_FILES) -o $@


$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<


run: $(APP_DIR)/$(APP_NAME)
	@$(APP_DIR)/$(APP_NAME)

clean:
	rm -f $(OBJ_FILES) 
	rm -f $(APP_DIR)/$(APP_NAME) 
	rm -f $(APP_DIR)/$(DEBUG_APP_NAME)
	rm -f $(DEB_FILES)
	clear

clear:
	rm -f $(OBJ_FILES) 
	rm -f $(APP_DIR)/$(APP_NAME) 
	rm -f $(APP_DIR)/$(DEBUG_APP_NAME)
	rm -f $(DEB_FILES)
	clear
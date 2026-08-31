#pragma once

// Shared input report sizes.  Keep these independent of the Win32
// configuration UI so the emulator core can consume them in AppContainer.
#define LIGHTGUN_NUM_BUTTONS 17
#define XBOX_CTRL_NUM_BUTTONS 25
#define SBC_NUM_BUTTONS 56
#define HIGHEST_NUM_BUTTONS SBC_NUM_BUTTONS

#define XBOX_BUTTON_NAME_LENGTH 30
#define HOST_BUTTON_NAME_LENGTH 30

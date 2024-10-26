#pragma once
#include <d3d9.h>
#include "../include.h"

namespace ui {
    inline LPDIRECT3DDEVICE9 dev;
    inline const char* window_title = "Prefetch Parser";
    inline ImVec2 screen_res = ImVec2(0, 0);
    inline ImVec2 window_pos = ImVec2(0, 0);
    inline ImVec2 window_size = ImVec2(1000, 750);
    inline ImVec2 original_window_size = ImVec2(1000, 750);

    inline DWORD window_flags = ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoScrollbar;
    inline bool is_maximized = false;
    inline std::vector<PrefetchFileInfo> file_infos;

    inline ImFont* smallFont;

    void init(LPDIRECT3DDEVICE9 device);
    void render();
    void initialize_prefetch_data();
    void toggle_maximize();
}

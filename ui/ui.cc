#include "ui.h"
#include <yara.h>


std::vector<LogonSessionInfo> GetInteractiveLogonSessions() {
    std::vector<LogonSessionInfo> sessions;
    ULONG logonSessionCount = 0;
    PLUID logonSessionList = NULL;
    NTSTATUS status = LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
    if (status != ERROR_SUCCESS) {
        return sessions;
    }

    for (ULONG i = 0; i < logonSessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = LsaGetLogonSessionData(&logonSessionList[i], &sessionData);
        if (status == ERROR_SUCCESS && sessionData != NULL) {
            if (sessionData->LogonType == Interactive ||
                sessionData->LogonType == RemoteInteractive) {
                LogonSessionInfo info;

                FILETIME utcLogonTime;
                utcLogonTime.dwLowDateTime = sessionData->LogonTime.LowPart;
                utcLogonTime.dwHighDateTime = sessionData->LogonTime.HighPart;

                FILETIME localLogonTime;
                FileTimeToLocalFileTime(&utcLogonTime, &localLogonTime);

                info.logonTime.dwLowDateTime = localLogonTime.dwLowDateTime;
                info.logonTime.dwHighDateTime = localLogonTime.dwHighDateTime;
                info.sessionId = sessionData->Session;
                info.isInteractive = true;
                sessions.push_back(info);
            }
            LsaFreeReturnBuffer(sessionData);
        }
    }
    LsaFreeReturnBuffer(logonSessionList);
    return sessions;
}

class TimeValidator {
public:
    static bool isValidFormat(const std::string& timeStr) {
        if (timeStr.length() != 19) return false;
        std::tm tm = {};
        std::istringstream ss(timeStr);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        return !ss.fail();
    }

    static bool isAfterLogonTime(const std::string& timeStr, const FILETIME& logonTime) {
        if (!isValidFormat(timeStr)) return false;

        std::tm tm = {};
        std::istringstream ss(timeStr);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

        SYSTEMTIME st = {
            (WORD)(tm.tm_year + 1900),
            (WORD)(tm.tm_mon + 1),
            (WORD)tm.tm_wday,
            (WORD)tm.tm_mday,
            (WORD)tm.tm_hour,
            (WORD)tm.tm_min,
            (WORD)tm.tm_sec,
            0
        };

        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        FILETIME localFt;
        FileTimeToLocalFileTime(&ft, &localFt);
        return CompareFileTime(&localFt, &logonTime) > 0;
    }

    static bool isInInstance(const std::string& execTime) {
    if (!isValidFormat(execTime)) return false;
    auto sessions = GetInteractiveLogonSessions();
    if (sessions.empty()) {
        return false;
    }
    const LogonSessionInfo& firstSession = sessions.front();
    SYSTEMTIME utcCurrentSysTime;
    GetSystemTime(&utcCurrentSysTime);
    FILETIME currentTime;
    SystemTimeToFileTime(&utcCurrentSysTime, &currentTime);
    std::tm tm = {};
    std::istringstream ss(execTime);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    SYSTEMTIME execSt = {
        (WORD)(tm.tm_year + 1900),
        (WORD)(tm.tm_mon + 1),
        (WORD)tm.tm_wday,
        (WORD)tm.tm_mday,
        (WORD)tm.tm_hour,
        (WORD)tm.tm_min,
        (WORD)tm.tm_sec,
        0
    };
    FILETIME execFt;
    SystemTimeToFileTime(&execSt, &execFt);
    return (CompareFileTime(&execFt, &firstSession.logonTime) >= 0 &&
            CompareFileTime(&execFt, &currentTime) <= 0);
}

};

void CopyableText(const char* label)
{
    ImGui::Text("%s", label);

    bool is_hovered = ImGui::IsItemHovered();
    bool is_ctrl_down = ImGui::GetIO().KeyCtrl;
    bool is_clicked = ImGui::IsItemClicked(1);

    if (is_hovered)
    {
        if (is_ctrl_down)
        {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        }

        if (is_ctrl_down && is_clicked)
        {
            ImGui::SetClipboardText(label);
        }
    }
}


std::vector<PrefetchFileInfo> GetPrefetchFileInfos() {
    std::vector<PrefetchFileInfo> file_infos;
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile("C:\\Windows\\Prefetch\\*.pf", &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        SYSTEMTIME lastLogonTime;
        FILETIME lastLogonFileTime;
        SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);
        std::unordered_set<std::wstring> processedFiles;
        do {
            std::string file_path = "C:\\Windows\\Prefetch\\" + std::string(findFileData.cFileName);
            const auto parser = prefetch_parser(file_path.c_str());
            if (parser.success()) {
                PrefetchFileInfo info;
                info.filename = findFileData.cFileName;
                info.executed_time = parser.executed_time();
                info.related_filenames = parser.get_filenames_strings();
                info.last_eight_execution_times = parser.last_eight_execution_times();
                info.readable_time = ConvertExecutedTime(info.executed_time);
                std::wstring properPath = GetDriveLetterFromVolumePath(StringToWString(info.filename));
                info.isInInstance = TimeValidator::isInInstance(info.readable_time);
                info.is_signed = IsFileSignatureValid(properPath);
                
                file_infos.push_back(info);
            }
        } while (FindNextFile(hFind, &findFileData));
        FindClose(hFind);
    }
    return file_infos;
}

void ui::initialize_prefetch_data() {
    file_infos = GetPrefetchFileInfos();

    for (auto& info : file_infos) {
        std::wstring prefetchFileName = StringToWString(info.filename);
        size_t hyphenPos = prefetchFileName.find(L'-');
        std::wstring fileNameFromPrefetch = (hyphenPos != std::wstring::npos) ? prefetchFileName.substr(0, hyphenPos) : prefetchFileName;

        for (const auto& filename : info.related_filenames) {
            std::wstring properPath = GetDriveLetterFromVolumePath(filename);
            if (properPath.find(fileNameFromPrefetch) != std::wstring::npos &&
                properPath.find(L'.') != std::wstring::npos) {
                info.proper_path = properPath;
                if (GetFileAttributesW(properPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    info.is_signed = false;
                    info.is_present = false;
                    info.matched_rules.push_back("none");
                }
                else {
                    info.is_signed = IsFileSignatureValid(properPath);
                    
                    if (!info.is_signed)
                    {
                        if (ToUpperCase(info.proper_path) == ToUpperCase(StringToWString(getOwnPath()))) {
                            
                        }
                        else {
                            std::vector<std::string> matched_rules;
                            bool yara_match = scan_with_yara(WStringToString(info.proper_path), matched_rules);
                            if (yara_match && !matched_rules.empty()) {
                                for (const auto& rule : matched_rules) {
                                    info.matched_rules.push_back(rule);
                                }
                            }
                            else {
                                info.matched_rules.push_back("none");
                            }
                        }
                    }
                    else
                    {
                        info.matched_rules.push_back("none");
                    }
                }
                break;
            }
        }
        info.signature_checked = true;
    }
}

void ui::render() {
    if (!globals.active) return;
    static bool show_unsigned_only = false;
    static bool show_flagged_only = false;
    static bool is_dragging = false;
    static ImVec2 drag_offset;
    static bool show_in_instance_only = false;
    static int selected_item = -1;
    static ImGuiTableSortSpecs* sorts_specs = NULL;
    static bool need_sort = false;
    static ImGuiTextBuffer debug_output;

    ImGui::SetNextWindowPos(window_pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(window_size, ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.0f);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(5, 5));

    ImGuiWindowFlags flags = window_flags | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize;
    ImGui::Begin(window_title, &globals.active, flags);
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9, 0));
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f, 0.2f, 0.3f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.3f, 0.4f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.2f, 0.3f, 1.0f));

        float title_bar_height = 30;
        ImGui::BeginChild("TitleBar", ImVec2(ImGui::GetWindowWidth(), title_bar_height), false, ImGuiWindowFlags_NoScrollbar);

        ImGui::SetCursorPosY((title_bar_height - ImGui::GetTextLineHeight()) * 0.5f);
        ImGui::Text("%s", window_title);

        float button_width = 35;
        float buttons_total_width = button_width * 2;
        float right_padding = 20;

        ImGui::SameLine(ImGui::GetWindowWidth() - buttons_total_width - right_padding);
        if (ImGui::Button(is_maximized ? "[-]" : "[+]", ImVec2(button_width, title_bar_height))) {
            toggle_maximize();
        }
        ImGui::SameLine();
        if (ImGui::Button("X", ImVec2(button_width, title_bar_height))) {
            globals.active = false;
        }

        ImVec2 title_bar_min = ImGui::GetWindowPos();
        ImVec2 title_bar_max = title_bar_min + ImGui::GetWindowSize();
        bool is_mouse_on_title_bar = ImGui::IsMouseHoveringRect(title_bar_min, title_bar_max);

        if (is_mouse_on_title_bar && ImGui::IsMouseClicked(0)) {
            is_dragging = true;
            drag_offset = ImGui::GetIO().MousePos - window_pos;
        }

        if (is_dragging) {
            if (ImGui::IsMouseDown(0)) {
                window_pos = ImGui::GetIO().MousePos - drag_offset;
            }
            else {
                is_dragging = false;
            }
        }

        ImGui::EndChild();

        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar();

        float content_height = ImGui::GetContentRegionAvail().y;
        float table_height = content_height * 0.55f;
        float details_height = content_height * 0.45f;

        ImGui::Checkbox("Show Unsigned Files Only", &show_unsigned_only);
        ImGui::SameLine();
        ImGui::Checkbox("Show Flagged Files Only", &show_flagged_only);
        ImGui::SameLine();
        ImGui::Checkbox("Only in Instance", &show_in_instance_only);
        ImGui::Separator();

        if (ImGui::BeginTable("PrefetchTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit, ImVec2(0, table_height))) {
            ImGui::TableSetupColumn("Last Exec", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("Present", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("Generics", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sorts_specs = ImGui::TableGetSortSpecs()) {
                if (sorts_specs->SpecsDirty || need_sort) {
                    need_sort = false;
                    std::sort(file_infos.begin(), file_infos.end(),
                        [sorts_specs](const auto& a, const auto& b) {
                            for (int n = 0; n < sorts_specs->SpecsCount; n++) {
                                const ImGuiTableColumnSortSpecs* sort_spec = &sorts_specs->Specs[n];
                                int delta = 0;
                                switch (sort_spec->ColumnIndex) {
                                case 0: delta = (a.readable_time > b.readable_time) ? 1 : ((a.readable_time < b.readable_time) ? -1 : 0); break;
                                case 1: delta = (a.is_signed == b.is_signed) ? 0 : (a.is_signed ? 1 : -1); break;
                                case 2: delta = (a.is_present == b.is_present) ? 0 : (a.is_present ? 1 : -1); break;
                                case 3: delta = a.proper_path.compare(b.proper_path); break;
                                case 4:
                                    if (!a.matched_rules.empty() && !b.matched_rules.empty()) {
                                        delta = a.matched_rules[0].compare(b.matched_rules[0]);
                                    }
                                    break;
                                }
                                if (delta > 0)
                                    return (sort_spec->SortDirection == ImGuiSortDirection_Ascending) ? false : true;
                                if (delta < 0)
                                    return (sort_spec->SortDirection == ImGuiSortDirection_Ascending) ? true : false;
                            }
                            return false;
                        });
                    sorts_specs->SpecsDirty = false;
                }
            }
            int displayed_index = 0;
            for (int i = 0; i < file_infos.size(); i++) {
                const auto& info = file_infos[i];
                bool should_display = true;

                if (show_unsigned_only && info.is_signed) {
                    should_display = false;
                }
                if (show_flagged_only) {
                    bool has_non_none_rule = false;
                    for (const auto& rule : info.matched_rules) {
                        if (rule != "none") {
                            has_non_none_rule = true;
                            break;
                        }
                    }
                    if (!has_non_none_rule) {
                        should_display = false;
                    }
                }
                if (show_in_instance_only && !info.isInInstance) {
                    should_display = false;
                }

                if (!should_display) {
                    continue;
                }

                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                bool is_selected = selected_item == i;

                std::string label = "##" + std::to_string(i);

                if (ImGui::Selectable(label.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns))
                {
                    selected_item = i;
                }
                ImGui::SameLine();
                CopyableText(info.readable_time.c_str());
                ImGui::TableNextColumn();
                if (!info.proper_path.empty())
                {
                    std::string path = WStringToString(info.proper_path);
                    CopyableText(path.c_str());
                }
                ImGui::TableNextColumn();
                if (info.is_signed)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
                }
                else
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                }
                CopyableText(info.is_signed ? "Signed" : "Unsigned");
                ImGui::PopStyleColor();
                ImGui::TableNextColumn();
                CopyableText(info.is_present ? "Yes" : "No");
                ImGui::TableNextColumn();
                for (const auto& rule : info.matched_rules)
                {
                    if (rule != "none")
                    {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                        CopyableText(("Rule [" + rule + "] ").c_str());
                        ImGui::PopStyleColor();
                        ImGui::SameLine();
                    }
                    else
                    {
                        CopyableText(rule.c_str());
                    }
                }
            }
            ImGui::EndTable();
        }

        ImGui::BeginChild("DetailsPane", ImVec2(0, details_height), true);
        if (selected_item >= 0 && selected_item < file_infos.size()) {
            const auto& selected_info = file_infos[selected_item];

            if (ImGui::BeginTabBar("DetailsTabs")) {
                if (ImGui::BeginTabItem("Related Files")) {
                    if (ImGui::BeginTable("RelatedFilesTable", 1, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                        ImGui::TableSetupColumn("Full Path");
                        ImGui::TableHeadersRow();

                        for (const auto& related_file : selected_info.related_filenames) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();

                            std::wstring convertedPath = GetDriveLetterFromVolumePath(related_file);
                            std::string narrow_filename = WStringToString(convertedPath);
                            ImGui::PushFont(ui::smallFont);
                            CopyableText(narrow_filename.c_str());
                            ImGui::PopFont();
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Execution History")) {
                    for (int i = 0; i < selected_info.last_eight_execution_times.size(); ++i) {
                        const auto& exec_time = selected_info.last_eight_execution_times[i];
                        if (exec_time != 0) {
                             std::string time_str = ConvertExecutedTime(exec_time);
                             ImGui::Text("Run %d: %s", i + 1, time_str.c_str());
                            
                        }
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("PF File Info")) {
                    std::string fullPath = "C:\\Windows\\Prefetch\\" + selected_info.filename;

                    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
                    if (GetFileAttributesExA(fullPath.c_str(), GetFileExInfoStandard, &fileInfo)) {
                        ImGui::Text("PF name: %s", selected_info.filename.c_str());

                        LARGE_INTEGER fileSize;
                        fileSize.HighPart = fileInfo.nFileSizeHigh;
                        fileSize.LowPart = fileInfo.nFileSizeLow;
                        ImGui::Text("File size: %.2f bytes", fileSize.QuadPart / 1024.0f);

                        ImGui::Text("Creation time: %s", GetFileTimeString(fileInfo.ftCreationTime).c_str());
                        ImGui::Text("Last access time: %s", GetFileTimeString(fileInfo.ftLastAccessTime).c_str());
                        ImGui::Text("Last modified time: %s", GetFileTimeString(fileInfo.ftLastWriteTime).c_str());
                        
                    }
                    ImGui::EndTabItem();
                }
            }
                ImGui::EndTabBar();
            
        }

            ImGui::EndChild();
    }
    ImGui::PopStyleVar();
    ImGui::End();
}


void ui::toggle_maximize() {
    if (is_maximized) {
        // Restore
        window_size = original_window_size;
        RECT screen_rect{};
        GetWindowRect(GetDesktopWindow(), &screen_rect);
        screen_res = ImVec2(float(screen_rect.right), float(screen_rect.bottom));
        window_pos = (screen_res - window_size) * 0.5f;
        is_maximized = false;
    }
    else {
        // Maximize
        RECT work_area;
        SystemParametersInfo(SPI_GETWORKAREA, 0, &work_area, 0);
        original_window_size = window_size;
        RECT screen_rect{};
        GetWindowRect(GetDesktopWindow(), &screen_rect);
        screen_res = ImVec2(float(screen_rect.right), float(screen_rect.bottom));
        window_pos = (screen_res - window_size) * 0.5f;
        window_size = ImVec2(work_area.right - work_area.left, work_area.bottom - work_area.top);
        window_pos = ImVec2(static_cast<float>(work_area.left), static_cast<float>(work_area.top));
        is_maximized = true;
    }
}
void ui::init(LPDIRECT3DDEVICE9 device) {
    dev = device;
    initializeGenericRules();
    initialize_prefetch_data();
    ImGui::StyleColorsDark();
    if (window_pos.x == 0) {
        RECT screen_rect{};
        GetWindowRect(GetDesktopWindow(), &screen_rect);
        screen_res = ImVec2(float(screen_rect.right), float(screen_rect.bottom));
        window_pos = (screen_res - window_size) * 0.5f;
    }
}

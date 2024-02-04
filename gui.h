#pragma once

// FTXUI stuff
#include "ftxui/component/component.hpp"
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/string.hpp>

namespace ArpChat
{
class ArpGui
{
  public:
    ArpGui();
    ~ArpGui() = default;

    auto getInputField() { return inputField; }

    ftxui::Component getVInputField();

    void prepareInputFieldForChat();

  public:
    std::string      inputBuffer;
    ftxui::Component inputField;
};
}   // namespace ArpChat

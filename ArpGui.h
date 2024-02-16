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
    explicit ArpGui();
    ~ArpGui() = default;

    auto getInputField() { return inputField; }

    ftxui::Component getVInputField();

    void prepareInputFieldForChat();

// Curently working on (TODO):
// Move all the screen stuff to this class because it does not make sense to have it in main.cpp
// Cleanup in main the duplicated code
  public:
    std::string                      inputBuffer;
    ftxui::Component                 inputField;
    ftxui::ScreenInteractive         screen;
};
}   // namespace ArpChat

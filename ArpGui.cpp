#include "ArpGui.h"

namespace ArpChat
{
using namespace ftxui;

//-----------------------------------------------------------------------------
ArpGui::ArpGui() : screen{ ftxui::ScreenInteractive::TerminalOutput() }
{
    inputField =
        ftxui::Input( &inputBuffer, "Type a message and press Enter..." );
}

//-----------------------------------------------------------------------------
void ArpGui::initRendererComponent( const std::deque<std::string>& chatHistory,
                                    ArpProtocol&                   arpProtocol )
{
    prepareChatInputField();
    renderer = Renderer(
        getVContainerInputField(),
        [ & ]
        {
            std::lock_guard<std::mutex> lock( arpProtocol.chatMutex );
            std::vector<Element> chatElements;
            for ( const auto& message : chatHistory )
            {
                chatElements.push_back( text( message ) );
            }

            // Combine the text elemebnts into a vbox
            // https://arthursonzogni.github.io/FTXUI/index.html#component-vertical
            auto tmpVbox = vbox( std::move( chatElements ) );

            // Create a vbox for the chatHistory and input field
            auto vboxWithInput =
                vbox( { text( L"Chat History" ) | hcenter, tmpVbox, separator(),
                        hbox( text( " Message Input : " ),
                              inputField->Render() ) } ) |
                border;

            return vboxWithInput;
        } );

    // Still need a fix for arpChat access
    component = CatchEvent(
        renderer,
        [ & ]( Event event )
        {
            if ( event == ftxui::Event::Character( 'q' ) )
            {
                screen.ExitLoopClosure();
                return true;
            }
            else if ( event == ftxui::Event::Return )
            {
                if ( arpProtocol.sendArpMessage(
                         inputBuffer, std::string( MESSAGE_PREFIX ) ) )
                {
                    postEvent( event );
                    inputBuffer.clear();
                    return true;
                }
                return false;
            }

            return false;
        } );
}

//-----------------------------------------------------------------------------
void ArpGui::run( const std::deque<std::string>& chatHistory,
                  ArpProtocol&                   arpProtocol )
{
    initRendererComponent( chatHistory, arpProtocol );

    screen.Loop( component );
}

//-----------------------------------------------------------------------------
void ArpGui::postEvent( ftxui::Event event )
{
    screen.PostEvent( event );
}

//-----------------------------------------------------------------------------
std::string ArpGui::registerMyself(
    std::map<std::string, std::string>& macToUsernameMapping )
{
    std::string firstName;

    // The basic input components:
    inputField = ftxui::Input( &inputBuffer, "Enter your username" );
    Component input_first_name = ftxui::Container::Vertical( {
        inputField,
    } );

    // The component tree:
    auto component = Container::Vertical( {
        getVContainerInputField(),
    } );

    // Tweak how the component tree is rendered:
    auto renderer = Renderer(
        component,
        [ & ]
        {
            return vbox( {
                       hbox( text( " Username : " ), inputField->Render() ),
                       text( "Hello " + inputBuffer ),
                   } ) |
                   border;
        } );

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    auto screen = ScreenInteractive::TerminalOutput();
    auto component_ =
        CatchEvent( renderer,
                    [ & ]( Event event )
                    {
                        if ( event == ftxui::Event::Return )
                        {
                            // Call your function to send
                            // messages.
                            macToUsernameMapping[ macToString( sourceMac ) ] =
                                inputBuffer;
                            screen.ExitLoopClosure()();
                            return true;
                        }
                        return false;
                    } );

    // Stuck in infinit loop until user confirms with enter
    screen.Loop( component_ );

    return inputBuffer;
}

//-----------------------------------------------------------------------------
ftxui::Component ArpGui::getVContainerInputField() const
{
    return ftxui::Container::Vertical( {
        inputField,
    } );
}

};   // namespace ArpChat

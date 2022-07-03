import PySimpleGUI as Sg
import analyzer

layout = [
    [Sg.Push(), Sg.Text("WELCOME TO PACKET ANALYZER", font='Times 17'), Sg.Push()],
    [Sg.Text("Please select a Wireshark file: ", size=(40, 1))],
    [Sg.FilesBrowse('Select', key="-directory-"), Sg.InputText(disabled=True, size=(91, 1))],
    [Sg.Button('Count'), Sg.Text("Number of packets in file is:"),
     Sg.InputText(disabled=True, key="-count-", size=(66, 1))],
    [Sg.Text("Select protocol type:"), Sg.InputText(size=(10, 1), key="-protocol-"), Sg.Button('Show info')],
    [Sg.Multiline(disabled=True, key="-info-", size=(100, 44))],
    [Sg.Exit(button_color='red')]
]

if __name__ == '__main__':

    window = Sg.Window(title="Packet analyzer", layout=layout, margins=(100, 100))

    while True:
        event, values = window.read()
        print(event, values)

        try:
            dirr = values["-directory-"]
            protocol = values["-protocol-"]
            inter = values["-interf-"]
        except (TypeError, KeyError):
            pass

        # Exit the program
        if event == Sg.WINDOW_CLOSED or event == 'Exit':
            break

        # Get directory
        if event == 'Select':
            dirr = values["-directory-"]

        # Count number of packets in file
        if event == 'Count':
            window["-count-"].update(analyzer.packets_count(dirr))

        # Show info from file
        if event == 'Show info':
            window["-info-"].update(analyzer.show_info(dirr, protocol))
    window.close()

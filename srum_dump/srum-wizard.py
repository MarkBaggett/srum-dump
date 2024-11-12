import PySimpleGUI as sg
import os
from pathlib import Path

def create_wizard_window(title, layout, size=(600, 400)):
    """Helper function to create consistent wizard windows"""
    return sg.Window(
        title,
        layout,
        size=size,
        element_justification='center',
        finalize=True,
        modal=True
    )

def extract_live_file():
    # Placeholder for live SRUM extraction
    return "C:\\Windows\\System32\\sru\\SRUDB.dat"

def step1_source_selection():
    layout = [
        [sg.Text("SRUM Source Selection", font=("Helvetica", 16))],
        [sg.Image(source="./holding_place.gif", key='-GIF-')],  # Replace with actual GIF path
        [sg.Text("Are you analyzing the SRUM in use on this computer\nor a SRUM extracted from another computer?")],
        [sg.Button("Local Computer"), sg.Button("External SRUM File")]
    ]
    
    window = create_wizard_window("Step 1: SRUM Source", layout)
    
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            window.close()
            return None
        if event == "Local Computer":
            srum_path = extract_live_file()
            window.close()
            return srum_path
        if event == "External SRUM File":
            window.close()
            filepath = sg.popup_get_file("Select SRUM File", file_types=(("SRUM Files", "*.dat"),))
            return filepath

def step2_registry_selection():
    layout = [
        [sg.Text("Registry File Selection", font=("Helvetica", 16))],
        [sg.Image(source="/path/to/gif/here", key='-GIF-')],  # Replace with actual GIF path
        [sg.Text("Please select the Registry file to use:")],
        [sg.Input(key='-REG-'), sg.FileBrowse(file_types=(("Registry Files", "*.dat *.hive"),))],
        [sg.Button("Next"), sg.Button("Back")]
    ]
    
    window = create_wizard_window("Step 2: Registry Selection", layout)
    
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Back"):
            window.close()
            return None, True if event == "Back" else False
        if event == "Next" and values['-REG-']:
            window.close()
            return values['-REG-'], False

def step3_template_selection():
    layout = [
        [sg.Text("Template Selection", font=("Helvetica", 16))],
        [sg.Image(source="/path/to/gif/here", key='-GIF-')],  # Replace with actual GIF path
        [sg.Text("Please select the template file:")],
        [sg.Input(key='-TEMPLATE-'), sg.FileBrowse(file_types=(("Template Files", "*.txt *.template"),))],
        [sg.Button("Next"), sg.Button("Back")]
    ]
    
    window = create_wizard_window("Step 3: Template Selection", layout)
    
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Back"):
            window.close()
            return None, True if event == "Back" else False
        if event == "Next" and values['-TEMPLATE-']:
            window.close()
            return values['-TEMPLATE-'], False

def step4_output_selection():
    layout = [
        [sg.Text("Output Location", font=("Helvetica", 16))],
        [sg.Image(source="/path/to/gif/here", key='-GIF-')],  # Replace with actual GIF path
        [sg.Text("Select where to save the output:")],
        [sg.Input(key='-OUTPUT-'), sg.SaveAs(file_types=(("CSV Files", "*.csv"),))],
        [sg.Button("Next"), sg.Button("Back")]
    ]
    
    window = create_wizard_window("Step 4: Output Selection", layout)
    
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Back"):
            window.close()
            return None, True if event == "Back" else False
        if event == "Next" and values['-OUTPUT-']:
            window.close()
            return values['-OUTPUT-'], False

def step5_parser_selection():
    layout = [
        [sg.Text("Parser Selection", font=("Helvetica", 16))],
        [sg.Image(source="/path/to/gif/here", key='-GIF-')],  # Replace with actual GIF path
        [sg.Text("Select the parsing engine to use:")],
        [sg.Radio("ESEDBLIB", "PARSER", key='-ESEDB-', default=True),
         sg.Radio("DISSECT", "PARSER", key='-DISSECT-')],
        [sg.Button("Finish"), sg.Button("Back")]
    ]
    
    window = create_wizard_window("Step 5: Parser Selection", layout)
    
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Back"):
            window.close()
            return None, True if event == "Back" else False
        if event == "Finish":
            parser = "ESEDBLIB" if values['-ESEDB-'] else "DISSECT"
            window.close()
            return parser, False

def show_processing_dialog():
    layout = [
        [sg.Text("Processing SRUM Data", font=("Helvetica", 16))],
        [sg.Image(source="/path/to/gif/here", key='-GIF-')],  # Replace with actual GIF path
        [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROGRESS-')],
        [sg.Text("Please wait while your SRUM data is being processed...", key='-STATUS-')]
    ]
    
    window = create_wizard_window("Processing", layout)
    progress_bar = window['-PROGRESS-']
    
    # Simulate processing
    for i in range(100):
        event, values = window.read(timeout=50)
        if event == sg.WIN_CLOSED:
            break
        progress_bar.update(i + 1)
    
    window.close()

def main():
    sg.theme('LightGrey1')
    
    # Store wizard responses
    config = {
        'srum_path': None,
        'registry_path': None,
        'template_path': None,
        'output_path': None,
        'parser': None
    }
    
    current_step = 1
    while current_step <= 5:
        if current_step == 1:
            config['srum_path'] = step1_source_selection()
            if config['srum_path'] is None:
                break
            current_step += 1
            
        elif current_step == 2:
            config['registry_path'], go_back = step2_registry_selection()
            if config['registry_path'] is None and not go_back:
                break
            current_step = 1 if go_back else 3
            
        elif current_step == 3:
            config['template_path'], go_back = step3_template_selection()
            if config['template_path'] is None and not go_back:
                break
            current_step = 2 if go_back else 4
            
        elif current_step == 4:
            config['output_path'], go_back = step4_output_selection()
            if config['output_path'] is None and not go_back:
                break
            current_step = 3 if go_back else 5
            
        elif current_step == 5:
            config['parser'], go_back = step5_parser_selection()
            if config['parser'] is None and not go_back:
                break
            current_step = 4 if go_back else 6
    
    if all(config.values()):
        show_processing_dialog()
        sg.popup("Analysis Complete!", f"Results saved to: {config['output_path']}")

if __name__ == '__main__':
    main()

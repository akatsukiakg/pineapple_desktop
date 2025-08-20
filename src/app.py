"""App launcher"""
from src.ui.main_window import MainWindow

def run():
    app = MainWindow()
    app.mainloop()

if __name__ == '__main__':
    run()

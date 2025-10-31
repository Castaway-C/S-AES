import tkinter as tk
from gui.main_window import SAESGUI


def main():
    """主函数"""
    root = tk.Tk()
    app = SAESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
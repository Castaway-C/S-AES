def setup_styles():
    """设置全局样式"""
    try:
        from tkinter import ttk
        
        try:
            # 尝试导入并使用 ttkthemes 来获得更好的外观
            from ttkthemes import ThemedStyle
            style = ThemedStyle()
            # 可选主题: 'arc', 'plastik', 'classic', 'default', 'clam', 'alt'
            style.set_theme("arc")
        except ImportError:
            # 回退到标准ttk样式
            style = ttk.Style()

        # 全局字体设置
        style.configure(".", font=('Arial', 10))

        # 标题样式
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 12, 'bold'), padding=(5, 5))

        # 标签和按钮
        style.configure('TLabel', padding=(5, 5))
        style.configure('TButton', padding=(10, 5), font=('Arial', 10, 'bold'))
        style.configure('Custom.TButton', font=('Arial', 10))

        # 标签框架
        style.configure('TLabelFrame', padding=(10, 10))
        style.configure('TLabelFrame.Label', font=('Arial', 11, 'bold'), padding=(5, 0))

        # 选项卡
        style.configure('TNotebook.Tab', padding=(10, 5), font=('Arial', 10, 'bold'))

        # 状态标签
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Status.TLabel', padding=(5, 2), relief=tk.SUNKEN)

    except Exception as e:
        print(f"样式设置失败: {e}")
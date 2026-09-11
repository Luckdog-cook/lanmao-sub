name: Huozhong Register

on:
  workflow_dispatch:   # 只支持手动触发（防止乱注册）

permissions:
  contents: write

jobs:
  register:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install system deps (tesseract)
        run: |
          sudo apt-get update
          sudo apt-get install -y tesseract-ocr

      - name: Install Python deps
        run: pip install requests pillow pytesseract

      - name: Run register
        env:
          REGISTER_COUNT: "3"   # 每次注册几个，可改
        run: python huozhong_register.py

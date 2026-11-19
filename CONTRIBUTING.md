# 🤝 Contributing

Ideas, attacks and fixes are welcome!

1. 🍴 Fork the repo and create a branch.
2. ⚙️ `pip install -e . pytest`
3. ✍️ Make your change. New attack techniques go in `leaktrap/generator.py` (`DIRECT` or `INDIRECT`).
4. ✅ Run `python -m pytest`. Every generated prompt is checked automatically to make sure it can be detected.
5. 📬 Open a pull request describing what you added and why.

Please keep attacks pointed at the **planted fake secret**. See [SECURITY.md](SECURITY.md).

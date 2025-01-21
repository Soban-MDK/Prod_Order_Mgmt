from App import create_app
# from flask_wtf.csrf import CSRFProtect


app = create_app()
# csrf = CSRFProtect(app)
# csrf.init_app(app)

if __name__ == "__main__":
    app.run(debug=True, port=5000, host='0.0.0.0')
    
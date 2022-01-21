import os
from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # secret key (change in prod!)
        SECRET_KEY="dev",
        # store the database in the instance folder
        DATABASE=os.path.join(app.instance_path, "flaskr.sqlite"),
    )

    if test_config is None:
        # load the config if not test mode
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config
        app.config.update(test_config)

    # check folder exist
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/hello")
    def hello():
        return "Hello, World!"

    # register the database
    from flaskr import db
    db.init_app(app)

    # Register/apply blueprints
    from flaskr import auth, blog
    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)
    app.add_url_rule("/", endpoint="index")

    return app

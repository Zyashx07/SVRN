from app import app, db, Message  # import your Flask app and models

with app.app_context():  # ⚡ this sets the Flask context
    Message.query.delete()  # delete all messages
    db.session.commit()
    print("✅ All messages deleted!")

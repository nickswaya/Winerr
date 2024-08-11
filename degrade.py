from app import app, User, db
from datetime import datetime, timedelta
import time


def degrade_scores():
    now = datetime.now()
    users = User.query.all()
    for user in users:
        print('Degrading User')
        time_diff = now - user.last_updated
        hours = time_diff.total_seconds() / 3600
        degrade_amount = int(hours)  # $1 per hour, convert to cents
        if degrade_amount > 0:
            print('User Zero')
            user.current_score = max(user.current_score - degrade_amount, 0)
            user.last_updated = now
            db.session.commit()

degrade_scores()
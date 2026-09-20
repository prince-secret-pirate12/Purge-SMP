import os
import re

from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for
)

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_socketio import SocketIO, join_room

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK APP
# =========================================================

app = Flask(
    __name__,
    instance_relative_config=True
)

os.makedirs(
    app.instance_path,
    exist_ok=True
)


# =========================================================
# DATABASE
# =========================================================
#
# Render par DATABASE_URL diya ho to PostgreSQL use hoga.
# Local computer par SQLite use hoga.
#

database_url = os.getenv("DATABASE_URL")

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )


app.config.update(

    SECRET_KEY=os.getenv(
        "SECRET_KEY",
        "dev-change-me"
    ),

    SQLALCHEMY_DATABASE_URI=(
        database_url
        or
        "sqlite:///" + os.path.join(
            app.instance_path,
            "purge_shop.db"
        )
    ),

    SQLALCHEMY_TRACK_MODIFICATIONS=False,

    # =====================================================
    # PERSISTENT LOGIN
    # =====================================================
    #
    # Player/Admin 30 days tak logged in reh sakte hain.
    #

    PERMANENT_SESSION_LIFETIME=timedelta(days=30),

    SESSION_COOKIE_HTTPONLY=True,

    SESSION_COOKIE_SAMESITE="Lax",

    SESSION_COOKIE_SECURE=(
        os.getenv(
            "COOKIE_SECURE",
            "false"
        ).lower() == "true"
    )
)


# =========================================================
# EXTENSIONS
# =========================================================

db = SQLAlchemy(app)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[
        "200 per hour"
    ]
)

socketio = SocketIO(app)


# =========================================================
# DATABASE MODELS
# =========================================================


class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    minecraft_username = db.Column(
        db.String(16),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    account_status = db.Column(
        db.String(20),
        default="Active",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    orders = db.relationship(
        "Order",
        backref="user",
        lazy=True
    )


class Rank(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(30),
        unique=True,
        nullable=False
    )

    price = db.Column(
        db.Integer,
        nullable=False
    )

    description = db.Column(
        db.String(255),
        nullable=False
    )

    enabled = db.Column(
        db.Boolean,
        default=True
    )

    orders = db.relationship(
        "Order",
        backref="rank",
        lazy=True
    )


class Order(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    rank_id = db.Column(
        db.Integer,
        db.ForeignKey("rank.id"),
        nullable=False
    )

    amount = db.Column(
        db.Integer,
        nullable=False
    )

    utr = db.Column(
        db.String(40),
        unique=True,
        nullable=False,
        index=True
    )

    payment_status = db.Column(
        db.String(30),
        default="Pending Verification",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    verified_at = db.Column(
        db.DateTime
    )


class Admin(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class AdminAuditLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    admin_id = db.Column(
        db.Integer,
        db.ForeignKey("admin.id"),
        nullable=False
    )

    action = db.Column(
        db.String(120),
        nullable=False
    )

    target_type = db.Column(
        db.String(30)
    )

    target_id = db.Column(
        db.Integer
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================================================
# PLAYER LOGIN REQUIRED
# =========================================================


def user_required(f):

    @wraps(f)
    def wrapped(*args, **kwargs):

        uid = session.get("user_id")

        user = (
            db.session.get(User, uid)
            if uid
            else None
        )

        if not user:

            return redirect(
                url_for(
                    "login",
                    next=request.path
                )
            )

        if user.account_status != "Active":

            session.pop(
                "user_id",
                None
            )

            session.pop(
                "cart",
                None
            )

            flash(
                "Your account is suspended.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        return f(
            *args,
            **kwargs
        )

    return wrapped


# =========================================================
# ADMIN LOGIN REQUIRED
# =========================================================


def admin_required(f):

    @wraps(f)
    def wrapped(*args, **kwargs):

        admin_id = session.get(
            "admin_id"
        )

        admin = (
            db.session.get(
                Admin,
                admin_id
            )
            if admin_id
            else None
        )

        if not admin:

            session.pop(
                "admin_id",
                None
            )

            return redirect(
                url_for(
                    "admin_login"
                )
            )

        return f(
            *args,
            **kwargs
        )

    return wrapped


# =========================================================
# GLOBAL TEMPLATE DATA
# =========================================================


@app.context_processor
def ctx():

    current_user = None

    if session.get("user_id"):

        current_user = db.session.get(
            User,
            session["user_id"]
        )

    return {

        "current_user": current_user,

        "cart_count": len(
            session.get(
                "cart",
                []
            )
        )
    }


# =========================================================
# DATABASE INITIAL SETUP
# =========================================================


def seed():

    db.create_all()

    ranks = [

        (
            "Aura",
            29,
            "Entry rank. Benefits coming soon."
        ),

        (
            "MVP",
            49,
            "Premium rank. Benefits coming soon."
        ),

        (
            "GOD",
            99,
            "Powerful rank. Benefits coming soon."
        ),

        (
            "Elite",
            149,
            "Elite rank. Benefits coming soon."
        ),

        (
            "Mythic",
            199,
            "Highest current rank. Benefits coming soon."
        )
    ]

    for name, price, description in ranks:

        existing_rank = Rank.query.filter_by(
            name=name
        ).first()

        if not existing_rank:

            db.session.add(

                Rank(
                    name=name,
                    price=price,
                    description=description
                )

            )

    admin_username = os.getenv(
        "ADMIN_USERNAME"
    )

    admin_password = os.getenv(
        "ADMIN_PASSWORD"
    )

    if admin_username and admin_password:

        existing_admin = Admin.query.filter_by(
            username=admin_username
        ).first()

        if not existing_admin:

            db.session.add(

                Admin(

                    username=admin_username,

                    password_hash=generate_password_hash(
                        admin_password
                    )

                )

            )

    db.session.commit()


with app.app_context():

    seed()


# =========================================================
# SOCKET.IO CONNECTION
# =========================================================
#
# Admin aur players ko alag rooms milte hain.
#
# Isse UTR/order information public users ko broadcast
# nahi hogi.
# =========================================================


@socketio.on("connect")
def socket_connect():

    admin_id = session.get(
        "admin_id"
    )

    user_id = session.get(
        "user_id"
    )

    if admin_id:

        admin = db.session.get(
            Admin,
            admin_id
        )

        if admin:

            join_room(
                "admins"
            )

    if user_id:

        user = db.session.get(
            User,
            user_id
        )

        if user:

            join_room(
                f"user_{user_id}"
            )


# =========================================================
# HOME
# =========================================================


@app.route("/")
def home():

    ranks = (

        Rank.query
        .filter_by(enabled=True)
        .order_by(Rank.price)
        .all()

    )

    return render_template(
        "index.html",
        ranks=ranks
    )


# =========================================================
# RANKS
# =========================================================


@app.route("/ranks")
def ranks():

    ranks_list = (

        Rank.query
        .filter_by(enabled=True)
        .order_by(Rank.price)
        .all()

    )

    return render_template(
        "ranks.html",
        ranks=ranks_list
    )


# =========================================================
# RANK DETAILS
# =========================================================


@app.route(
    "/rank/<int:rid>"
)
def rank_detail(rid):

    rank = Rank.query.filter_by(
        id=rid,
        enabled=True
    ).first_or_404()

    return render_template(
        "rank_detail.html",
        rank=rank
    )


# =========================================================
# REGISTER
# =========================================================


@app.route(
    "/register",
    methods=[
        "GET",
        "POST"
    ]
)
@limiter.limit(
    "10 per hour"
)
def register():

    if request.method == "POST":

        name = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm = request.form.get(
            "confirm",
            ""
        )

        if not re.fullmatch(
            r"[A-Za-z0-9_]{3,16}",
            name
        ):

            flash(
                "Use a valid Minecraft username (3-16 letters, numbers, underscore).",
                "error"
            )

        elif password != confirm:

            flash(
                "Passwords do not match.",
                "error"
            )

        elif len(password) < 8:

            flash(
                "Password must be at least 8 characters.",
                "error"
            )

        elif User.query.filter(

            db.func.lower(
                User.minecraft_username
            ) == name.lower()

        ).first():

            flash(
                "Username already registered.",
                "error"
            )

        else:

            user = User(

                minecraft_username=name,

                password_hash=generate_password_hash(
                    password
                )

            )

            db.session.add(
                user
            )

            db.session.commit()

            # ---------------------------------------------
            # IMPORTANT
            #
            # session.clear() intentionally NOT used.
            #
            # Isse admin login delete nahi hoga.
            # ---------------------------------------------

            session.permanent = True

            session["user_id"] = user.id

            flash(
                "Account created!",
                "success"
            )

            return redirect(
                url_for("home")
            )

    return render_template(
        "register.html"
    )


# =========================================================
# PLAYER LOGIN
# =========================================================


@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
@limiter.limit(
    "10 per minute"
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip().lower()

        user = User.query.filter(

            db.func.lower(
                User.minecraft_username
            ) == username

        ).first()

        password = request.form.get(
            "password",
            ""
        )

        if (
            user
            and
            check_password_hash(
                user.password_hash,
                password
            )
        ):

            if user.account_status != "Active":

                flash(
                    "Your account is suspended.",
                    "error"
                )

            else:

                # =========================================
                # PERSISTENT LOGIN
                # =========================================

                session.permanent = True

                session["user_id"] = user.id

                # -----------------------------------------
                # IMPORTANT:
                #
                # admin_id ko remove nahi kar rahe.
                #
                # Player + Admin ek hi browser mein
                # simultaneously login reh sakte hain.
                # -----------------------------------------

                next_page = request.args.get(
                    "next",
                    ""
                )

                if (
                    next_page.startswith("/")
                    and
                    not next_page.startswith("//")
                ):

                    return redirect(
                        next_page
                    )

                return redirect(
                    url_for("home")
                )

        else:

            flash(
                "Invalid username or password.",
                "error"
            )

    return render_template(
        "login.html"
    )


# =========================================================
# PLAYER LOGOUT
# =========================================================


@app.post(
    "/logout"
)
def logout():

    # Player logout se admin logout nahi hoga.

    session.pop(
        "user_id",
        None
    )

    session.pop(
        "cart",
        None
    )

    return redirect(
        url_for("home")
    )


# =========================================================
# ADD TO CART
# =========================================================


@app.post(
    "/cart/add/<int:rid>"
)
@user_required
def cart_add(rid):

    Rank.query.filter_by(
        id=rid,
        enabled=True
    ).first_or_404()

    cart_items = session.get(
        "cart",
        []
    )

    if rid not in cart_items:

        cart_items.append(
            rid
        )

        session["cart"] = cart_items

        flash(
            "Rank added to cart.",
            "success"
        )

    else:

        flash(
            "That rank is already in your cart.",
            "info"
        )

    return redirect(

        request.referrer
        or
        url_for("cart")

    )


# =========================================================
# CART
# =========================================================


@app.route(
    "/cart"
)
@user_required
def cart():

    ids = session.get(
        "cart",
        []
    )

    if ids:

        items = Rank.query.filter(
            Rank.id.in_(ids)
        ).all()

    else:

        items = []

    total = sum(
        item.price
        for item in items
    )

    return render_template(

        "cart.html",

        items=items,

        total=total

    )


# =========================================================
# REMOVE FROM CART
# =========================================================


@app.post(
    "/cart/remove/<int:rid>"
)
@user_required
def cart_remove(rid):

    session["cart"] = [

        item_id

        for item_id
        in session.get(
            "cart",
            []
        )

        if item_id != rid

    ]

    return redirect(
        url_for("cart")
    )


# =========================================================
# CHECKOUT
# =========================================================


@app.route(
    "/checkout/<int:rid>",
    methods=[
        "GET",
        "POST"
    ]
)
@user_required
@limiter.limit(
    "20 per hour"
)
def checkout(rid):

    rank = Rank.query.filter_by(

        id=rid,

        enabled=True

    ).first_or_404()

    if request.method == "POST":

        utr = request.form.get(
            "utr",
            ""
        ).strip()

        if not re.fullmatch(
            r"[A-Za-z0-9-]{6,40}",
            utr
        ):

            flash(
                "Enter a valid UTR / Transaction ID.",
                "error"
            )

        elif Order.query.filter_by(
            utr=utr
        ).first():

            flash(
                "This UTR has already been submitted.",
                "error"
            )

        else:

            order = Order(

                user_id=session[
                    "user_id"
                ],

                rank_id=rank.id,

                amount=rank.price,

                utr=utr

            )

            db.session.add(
                order
            )

            db.session.commit()

            # Remove purchased rank from cart.

            session["cart"] = [

                item_id

                for item_id
                in session.get(
                    "cart",
                    []
                )

                if item_id != rank.id

            ]

            # =============================================
            # LIVE ORDER
            # =============================================
            #
            # Player UTR submit karte hi
            # admin room ko live order event milega.
            #
            # Normal users ko UTR broadcast nahi hoga.
            # =============================================

            socketio.emit(

                "new_order",

                {

                    "id":
                        order.id,

                    "username":
                        order.user.minecraft_username,

                    "rank":
                        order.rank.name,

                    "amount":
                        order.amount,

                    "utr":
                        order.utr,

                    "status":
                        order.payment_status,

                    "created_at":
                        order.created_at.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "url":
                        url_for(
                            "admin_order",
                            oid=order.id
                        )

                },

                to="admins"

            )

            return render_template(

                "payment_success.html",

                order=order

            )

    return render_template(

        "checkout.html",

        rank=rank

    )


# =========================================================
# PLAYER PROFILE
# =========================================================


@app.route(
    "/profile"
)
@user_required
def profile():

    user = db.session.get(

        User,

        session[
            "user_id"
        ]

    )

    orders = (

        Order.query

        .filter_by(
            user_id=user.id
        )

        .order_by(
            Order.created_at.desc()
        )

        .all()

    )

    return render_template(

        "profile.html",

        user=user,

        orders=orders

    )


# =========================================================
# ADMIN LOGIN
# =========================================================


@app.route(
    "/admin/login",
    methods=[
        "GET",
        "POST"
    ]
)
@limiter.limit(
    "10 per minute"
)
def admin_login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        admin = Admin.query.filter_by(
            username=username
        ).first()

        if (
            admin
            and
            check_password_hash(
                admin.password_hash,
                password
            )
        ):

            # =============================================
            # PERSISTENT ADMIN LOGIN
            # =============================================

            session.permanent = True

            session[
                "admin_id"
            ] = admin.id

            # IMPORTANT:
            # user_id remove nahi hoga.
            #
            # Admin + Player same browser mein
            # login reh sakte hain.

            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )

        flash(
            "Invalid admin credentials.",
            "error"
        )

    return render_template(
        "admin/login.html"
    )


# =========================================================
# ADMIN LOGOUT
# =========================================================


@app.post(
    "/admin/logout"
)
@admin_required
def admin_logout():

    # Admin logout se player logout nahi hoga.

    session.pop(
        "admin_id",
        None
    )

    return redirect(
        url_for(
            "admin_login"
        )
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================


@app.route(
    "/admin"
)
@admin_required
def admin_dashboard():

    stats = {

        "users":
            User.query.count(),

        "orders":
            Order.query.count(),

        "pending":
            Order.query.filter_by(
                payment_status=
                "Pending Verification"
            ).count(),

        "approved":
            Order.query.filter_by(
                payment_status=
                "Approved"
            ).count(),

        "rejected":
            Order.query.filter_by(
                payment_status=
                "Rejected"
            ).count(),

        "revenue":

            db.session.query(

                db.func.coalesce(

                    db.func.sum(
                        Order.amount
                    ),

                    0

                )

            )

            .filter(
                Order.payment_status
                ==
                "Approved"
            )

            .scalar()

    }

    recent_orders = (

        Order.query

        .order_by(
            Order.created_at.desc()
        )

        .limit(10)

        .all()

    )

    return render_template(

        "admin/dashboard.html",

        stats=stats,

        orders=recent_orders

    )


# =========================================================
# ADMIN ALL ORDERS
# =========================================================


@app.route(
    "/admin/orders"
)
@admin_required
def admin_orders():

    query = (

        Order.query

        .join(User)

        .join(Rank)

    )

    search = request.args.get(
        "q",
        ""
    ).strip()

    status = request.args.get(
        "status",
        ""
    )

    if search:

        query = query.filter(

            db.or_(

                User.minecraft_username.ilike(
                    f"%{search}%"
                ),

                Order.utr.ilike(
                    f"%{search}%"
                ),

                Rank.name.ilike(
                    f"%{search}%"
                )

            )

        )

    if status:

        query = query.filter(

            Order.payment_status
            ==
            status

        )

    orders = (

        query

        .order_by(
            Order.created_at.desc()
        )

        .all()

    )

    return render_template(

        "admin/orders.html",

        orders=orders

    )


# =========================================================
# ADMIN ORDER DETAILS
# =========================================================


@app.route(
    "/admin/order/<int:oid>"
)
@admin_required
def admin_order(oid):

    order = Order.query.get_or_404(
        oid
    )

    return render_template(

        "admin/order_detail.html",

        order=order

    )


# =========================================================
# APPROVE / REJECT ORDER
# =========================================================


@app.post(
    "/admin/order/<int:oid>/<action>"
)
@admin_required
def admin_order_action(
    oid,
    action
):

    if action not in (
        "approve",
        "reject"
    ):

        abort(400)

    order = Order.query.get_or_404(
        oid
    )

    if action == "approve":

        order.payment_status = (
            "Approved"
        )

    else:

        order.payment_status = (
            "Rejected"
        )

    order.verified_at = (
        datetime.utcnow()
    )

    audit = AdminAuditLog(

        admin_id=session[
            "admin_id"
        ],

        action=f"{action} order",

        target_type="order",

        target_id=order.id

    )

    db.session.add(
        audit
    )

    db.session.commit()

    # =============================================
    # LIVE STATUS UPDATE
    # =============================================

    update = {

        "id":
            order.id,

        "status":
            order.payment_status,

        "verified_at":
            order.verified_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    }

    # All logged-in admin pages

    socketio.emit(

        "order_updated",

        update,

        to="admins"

    )

    # Only correct player

    socketio.emit(

        "order_updated",

        update,

        to=f"user_{order.user_id}"

    )

    flash(
        "Order updated.",
        "success"
    )

    return redirect(

        url_for(
            "admin_order",
            oid=oid
        )

    )


# =========================================================
# ADMIN USERS
# =========================================================


@app.route(
    "/admin/users"
)
@admin_required
def admin_users():

    users = (

        User.query

        .order_by(
            User.created_at.desc()
        )

        .all()

    )

    return render_template(

        "admin/users.html",

        users=users

    )


# =========================================================
# ADMIN USER DETAILS
# =========================================================


@app.route(
    "/admin/user/<int:uid>"
)
@admin_required
def admin_user(uid):

    user = User.query.get_or_404(
        uid
    )

    return render_template(

        "admin/user_detail.html",

        user=user

    )


# =========================================================
# SUSPEND / RESTORE USER
# =========================================================


@app.post(
    "/admin/user/<int:uid>/<action>"
)
@admin_required
def admin_user_action(
    uid,
    action
):

    if action not in (
        "suspend",
        "restore"
    ):

        abort(400)

    user = User.query.get_or_404(
        uid
    )

    if action == "suspend":

        user.account_status = (
            "Suspended"
        )

    else:

        user.account_status = (
            "Active"
        )

    audit = AdminAuditLog(

        admin_id=session[
            "admin_id"
        ],

        action=f"{action} user",

        target_type="user",

        target_id=user.id

    )

    db.session.add(
        audit
    )

    db.session.commit()

    # Tell only this player.

    socketio.emit(

        "account_status_updated",

        {
            "status":
                user.account_status
        },

        to=f"user_{user.id}"

    )

    flash(
        "User updated.",
        "success"
    )

    return redirect(

        url_for(
            "admin_user",
            uid=uid
        )

    )


# =========================================================
# RUN APP
# =========================================================


if __name__ == "__main__":

    socketio.run(
        app,
        debug=True
    )
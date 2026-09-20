import os, re
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app=Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)
app.config.update(
 SECRET_KEY=os.getenv('SECRET_KEY','dev-change-me'),
 SQLALCHEMY_DATABASE_URI='sqlite:///'+os.path.join(app.instance_path,'purge_shop.db'),
 SQLALCHEMY_TRACK_MODIFICATIONS=False,
 SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
 SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','false').lower()=='true')
db=SQLAlchemy(app); csrf=CSRFProtect(app); limiter=Limiter(get_remote_address, app=app, default_limits=['200 per hour'])

class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); minecraft_username=db.Column(db.String(16),unique=True,nullable=False,index=True); password_hash=db.Column(db.String(255),nullable=False); account_status=db.Column(db.String(20),default='Active',nullable=False); created_at=db.Column(db.DateTime,default=datetime.utcnow,nullable=False)
 orders=db.relationship('Order',backref='user',lazy=True)
class Rank(db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(30),unique=True,nullable=False); price=db.Column(db.Integer,nullable=False); description=db.Column(db.String(255),nullable=False); enabled=db.Column(db.Boolean,default=True)
 orders=db.relationship('Order',backref='rank',lazy=True)
class Order(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False); rank_id=db.Column(db.Integer,db.ForeignKey('rank.id'),nullable=False); amount=db.Column(db.Integer,nullable=False); utr=db.Column(db.String(40),unique=True,nullable=False,index=True); payment_status=db.Column(db.String(30),default='Pending Verification',nullable=False); created_at=db.Column(db.DateTime,default=datetime.utcnow,nullable=False); verified_at=db.Column(db.DateTime)
class Admin(db.Model):
 id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False); password_hash=db.Column(db.String(255),nullable=False); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class AdminAuditLog(db.Model):
 id=db.Column(db.Integer,primary_key=True); admin_id=db.Column(db.Integer,db.ForeignKey('admin.id'),nullable=False); action=db.Column(db.String(120),nullable=False); target_type=db.Column(db.String(30)); target_id=db.Column(db.Integer); created_at=db.Column(db.DateTime,default=datetime.utcnow)

def user_required(f):
 @wraps(f)
 def w(*a,**k):
  uid=session.get('user_id'); u=db.session.get(User,uid) if uid else None
  if not u: return redirect(url_for('login',next=request.path))
  if u.account_status!='Active': session.pop('user_id',None); flash('Your account is suspended.','error'); return redirect(url_for('login'))
  return f(*a,**k)
 return w
def admin_required(f):
 @wraps(f)
 def w(*a,**k):
  if not session.get('admin_id'): return redirect(url_for('admin_login'))
  return f(*a,**k)
 return w
@app.context_processor
def ctx():
 u=db.session.get(User,session.get('user_id')) if session.get('user_id') else None
 return {'current_user':u,'cart_count':len(session.get('cart',[]))}

def seed():
 db.create_all()
 ranks=[('Aura',29,'Entry rank. Benefits coming soon.'),('MVP',49,'Premium rank. Benefits coming soon.'),('GOD',99,'Powerful rank. Benefits coming soon.'),('Elite',149,'Elite rank. Benefits coming soon.'),('Mythic',199,'Highest current rank. Benefits coming soon.')]
 for n,p,d in ranks:
  if not Rank.query.filter_by(name=n).first(): db.session.add(Rank(name=n,price=p,description=d))
 au=os.getenv('ADMIN_USERNAME'); ap=os.getenv('ADMIN_PASSWORD')
 if au and ap and not Admin.query.filter_by(username=au).first(): db.session.add(Admin(username=au,password_hash=generate_password_hash(ap)))
 db.session.commit()
with app.app_context(): seed()

@app.route('/')
def home(): return render_template('index.html',ranks=Rank.query.filter_by(enabled=True).order_by(Rank.price).all())
@app.route('/ranks')
def ranks(): return render_template('ranks.html',ranks=Rank.query.filter_by(enabled=True).order_by(Rank.price).all())
@app.route('/rank/<int:rid>')
def rank_detail(rid): return render_template('rank_detail.html',rank=Rank.query.filter_by(id=rid,enabled=True).first_or_404())
@app.route('/register',methods=['GET','POST'])
@limiter.limit('10 per hour')
def register():
 if request.method=='POST':
  name=request.form.get('username','').strip(); pw=request.form.get('password',''); confirm=request.form.get('confirm','')
  if not re.fullmatch(r'[A-Za-z0-9_]{3,16}',name): flash('Use a valid Minecraft username (3-16 letters, numbers, underscore).','error')
  elif pw!=confirm: flash('Passwords do not match.','error')
  elif len(pw)<8: flash('Password must be at least 8 characters.','error')
  elif User.query.filter(db.func.lower(User.minecraft_username)==name.lower()).first(): flash('Username already registered.','error')
  else:
   u=User(minecraft_username=name,password_hash=generate_password_hash(pw)); db.session.add(u); db.session.commit(); session.clear(); session['user_id']=u.id; flash('Account created!','success'); return redirect(url_for('home'))
 return render_template('register.html')
@app.route('/login',methods=['GET','POST'])
@limiter.limit('10 per minute')
def login():
 if request.method=='POST':
  u=User.query.filter(db.func.lower(User.minecraft_username)==request.form.get('username','').strip().lower()).first()
  if u and check_password_hash(u.password_hash,request.form.get('password','')):
   if u.account_status!='Active': flash('Your account is suspended.','error')
   else: session.clear(); session['user_id']=u.id; return redirect(url_for('home'))
  else: flash('Invalid username or password.','error')
 return render_template('login.html')
@app.post('/logout')
def logout(): session.clear(); return redirect(url_for('home'))
@app.post('/cart/add/<int:rid>')
@user_required
def cart_add(rid):
 Rank.query.filter_by(id=rid,enabled=True).first_or_404(); c=session.get('cart',[])
 if rid not in c: c.append(rid); session['cart']=c; flash('Rank added to cart.','success')
 else: flash('That rank is already in your cart.','info')
 return redirect(request.referrer or url_for('cart'))
@app.route('/cart')
@user_required
def cart():
 ids=session.get('cart',[]); items=Rank.query.filter(Rank.id.in_(ids)).all() if ids else []; return render_template('cart.html',items=items,total=sum(x.price for x in items))
@app.post('/cart/remove/<int:rid>')
@user_required
def cart_remove(rid): session['cart']=[x for x in session.get('cart',[]) if x!=rid]; return redirect(url_for('cart'))
@app.route('/checkout/<int:rid>',methods=['GET','POST'])
@user_required
@limiter.limit('20 per hour')
def checkout(rid):
 rank=Rank.query.filter_by(id=rid,enabled=True).first_or_404()
 if request.method=='POST':
  utr=request.form.get('utr','').strip()
  if not re.fullmatch(r'[A-Za-z0-9-]{6,40}',utr): flash('Enter a valid UTR / Transaction ID.','error')
  elif Order.query.filter_by(utr=utr).first(): flash('This UTR has already been submitted.','error')
  else:
   o=Order(user_id=session['user_id'],rank_id=rank.id,amount=rank.price,utr=utr); db.session.add(o); db.session.commit(); session['cart']=[x for x in session.get('cart',[]) if x!=rank.id]; return render_template('payment_success.html',order=o)
 return render_template('checkout.html',rank=rank)
@app.route('/profile')
@user_required
def profile():
 u=db.session.get(User,session['user_id']); orders=Order.query.filter_by(user_id=u.id).order_by(Order.created_at.desc()).all(); return render_template('profile.html',user=u,orders=orders)

@app.route('/admin/login',methods=['GET','POST'])
@limiter.limit('10 per minute')
def admin_login():
 if request.method=='POST':
  a=Admin.query.filter_by(username=request.form.get('username','').strip()).first()
  if a and check_password_hash(a.password_hash,request.form.get('password','')): session.clear(); session['admin_id']=a.id; return redirect(url_for('admin_dashboard'))
  flash('Invalid admin credentials.','error')
 return render_template('admin/login.html')
@app.post('/admin/logout')
@admin_required
def admin_logout(): session.clear(); return redirect(url_for('admin_login'))
@app.route('/admin')
@admin_required
def admin_dashboard():
 stats={'users':User.query.count(),'orders':Order.query.count(),'pending':Order.query.filter_by(payment_status='Pending Verification').count(),'approved':Order.query.filter_by(payment_status='Approved').count(),'rejected':Order.query.filter_by(payment_status='Rejected').count(),'revenue':db.session.query(db.func.coalesce(db.func.sum(Order.amount),0)).filter(Order.payment_status=='Approved').scalar()}
 return render_template('admin/dashboard.html',stats=stats,orders=Order.query.order_by(Order.created_at.desc()).limit(10).all())
@app.route('/admin/orders')
@admin_required
def admin_orders():
 q=Order.query.join(User).join(Rank); s=request.args.get('q','').strip(); status=request.args.get('status','')
 if s: q=q.filter(db.or_(User.minecraft_username.ilike(f'%{s}%'),Order.utr.ilike(f'%{s}%'),Rank.name.ilike(f'%{s}%')))
 if status: q=q.filter(Order.payment_status==status)
 return render_template('admin/orders.html',orders=q.order_by(Order.created_at.desc()).all())
@app.route('/admin/order/<int:oid>')
@admin_required
def admin_order(oid): return render_template('admin/order_detail.html',order=Order.query.get_or_404(oid))
@app.post('/admin/order/<int:oid>/<action>')
@admin_required
def admin_order_action(oid,action):
 if action not in ('approve','reject'): abort(400)
 o=Order.query.get_or_404(oid); o.payment_status='Approved' if action=='approve' else 'Rejected'; o.verified_at=datetime.utcnow(); db.session.add(AdminAuditLog(admin_id=session['admin_id'],action=f'{action} order',target_type='order',target_id=o.id)); db.session.commit(); flash('Order updated.','success'); return redirect(url_for('admin_order',oid=oid))
@app.route('/admin/users')
@admin_required
def admin_users(): return render_template('admin/users.html',users=User.query.order_by(User.created_at.desc()).all())
@app.route('/admin/user/<int:uid>')
@admin_required
def admin_user(uid): return render_template('admin/user_detail.html',user=User.query.get_or_404(uid))
@app.post('/admin/user/<int:uid>/<action>')
@admin_required
def admin_user_action(uid,action):
 if action not in ('suspend','restore'): abort(400)
 u=User.query.get_or_404(uid); u.account_status='Suspended' if action=='suspend' else 'Active'; db.session.add(AdminAuditLog(admin_id=session['admin_id'],action=f'{action} user',target_type='user',target_id=u.id)); db.session.commit(); flash('User updated.','success'); return redirect(url_for('admin_user',uid=uid))

if __name__=='__main__': app.run(debug=True)

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import google.generativeai as genai
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session
import random
import string

app = Flask(__name__)

# 시크릿 키 설정 (실제 서비스에서는 환경 변수로 관리하는 것이 좋습니다)
app.secret_key = os.urandom(24)

# 업로드 설정
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 최대 16MB 제한

# 허용할 이미지 확장자
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# 업로드 폴더가 없으면 생성
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 사용자 데이터 저장 (실제로는 데이터베이스 사용)
users = {}

# Gemini API 설정
GOOGLE_API_KEY = "AIzaSyCviAJm0I8zVXzyTR_KgbDMofnJ6fqtpxU"
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# 게시글과 댓글을 저장할 리스트
posts = []
comments = []  # 댓글 저장용 리스트

# 페이지당 게시글 수 설정
POSTS_PER_PAGE = 10

# 욕설 필터링 및 도배 방지 설정 강화
FORBIDDEN_WORDS = [
    '씨발', '개새끼', '병신', '지랄', '닥쳐', '죽어', 
    '새끼', '시발', '좆', '놈', '년', '닥치고',
    'ㅅㅂ', 'ㅄ', 'ㅂㅅ', 'ㅈㄹ', 'ㄷㅊ',  # 초성 욕설
    'si bal', 'tq', 'fuck', 'shit',  # 변형 욕설
    '광고', '홍보', '대출', '인전화',  # 스팸 키워드
]

# IP별 작성 기록 및 제한 설정
POST_HISTORY = {}
COMMENT_HISTORY = {}
SPAM_BLOCK_LIST = set()  # 스팸 차단 IP 목록

# 도배 방지 설정 강화
POST_INTERVAL = 30  # 게시글 작성 간격 (초)
COMMENT_INTERVAL = 10  # 댓글 작성 간격 (초)
MAX_POSTS_PER_DAY = 10  # 하루 최대 게시글 수
MAX_COMMENTS_PER_DAY = 30  # 하루 최대 댓글 수
MAX_SAME_CONTENT = 3  # 동일 내용 최대 허용 횟수

# 앱 설정에 영구 세션 설정 추가
app.permanent_session_lifetime = timedelta(days=30)  # 30일 동안 유지

# 게스트 계정 정보
GUEST_PREFIX = "guest_"
guest_count = 0

# 프로필 댓글을 저장할 리스트
profile_comments = []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_content(text):
    """내용 검사 (욕설, 스팸)"""
    # 욕설 검사
    text_lower = text.lower().replace(' ', '')
    for word in FORBIDDEN_WORDS:
        if word in text_lower:
            return False, "부적절한 표현이 포함되어 있습니다."
    
    # 스팸 패턴 검사
    if text.count('http') > 2 or text.count('www.') > 2:
        return False, "과도한 링크가 포함되어 있습니다."
    
    if len(text) > 1000:
        return False, "내용이 너무 깁니다."
        
    return True, None

def check_spam_activity(history, user_ip, content, interval, max_per_day):
    """도배 검사"""
    current_time = datetime.now()
    
    # 차단된 IP 검사
    if user_ip in SPAM_BLOCK_LIST:
        return False, "스팸 활동으로 인해 차단되었습니다."
    
    # IP 기록 초기화
    if user_ip not in history:
        history[user_ip] = {
            'times': [],
            'contents': []
        }
    
    # 24시간이 지난 기록 삭제
    history[user_ip]['times'] = [
        time for time in history[user_ip]['times']
        if time > current_time - timedelta(days=1)
    ]
    
    # 최근 작성 간격 검사
    if history[user_ip]['times'] and \
       (current_time - history[user_ip]['times'][-1]).total_seconds() < interval:
        return False, f"{interval}초 후에 다시 시도해주세요."
    
    # 하루 최대 작성 수 검사
    if len(history[user_ip]['times']) >= max_per_day:
        return False, f"하루 최대 {max_per_day}회만 작성할 수 있습니다."
    
    # 동일 내용 도배 검사
    same_content_count = history[user_ip]['contents'].count(content)
    if same_content_count >= MAX_SAME_CONTENT:
        SPAM_BLOCK_LIST.add(user_ip)  # 스팸 차단 목록에 추가
        return False, "동일한 내용을 반복 게시하여 차단되었습니다."
    
    # 기록 추가
    history[user_ip]['times'].append(current_time)
    history[user_ip]['contents'].append(content)
    
    return True, None

# 파일 업로드 관련 함수 추가
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/health-consult')
def health_consult():
    return render_template('health_consult.html')

@app.route('/disease-management')
def disease_management():
    return render_template('disease_management.html')

@app.route('/emergency-guide')
def emergency_guide():
    return render_template('emergency_guide.html')

@app.route('/allergy-info')
def allergy_info():
    return render_template('allergy_info.html')

@app.route('/get-ai-response', methods=['POST'])
def get_ai_response():
    try:
        data = request.json
        user_message = data.get('message', '')
        
        # Gemini AI 응답 생성
        response = model.generate_content(
            f"""당신은 반려동물 건강 전문가입니다. 
            마크다운이나 특수문자를 사용하지 말고 일반 텍스트로만 답변해주세요.
            다음 질문에 답변해주세요: {user_message}"""
        )
        
        # 마크다운 형식과 특수문자 제거
        ai_response = response.text.replace('*', '').replace('_', '').replace('#', '')
        return jsonify({"response": ai_response})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": "AI 서비스 연결에 실패했습니다."}), 500

@app.route('/board')
def board():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    
    if search_query:
        # 검색 결과 필터링
        filtered_posts = [
            post for post in posts
            if search_query.lower() in post['title'].lower() or
               search_query.lower() in post['content'].lower() or
               search_query.lower() in post['author'].lower()
        ]
    else:
        filtered_posts = posts

    # 전체 페이지 수 계산
    total_posts = len(filtered_posts)
    total_pages = (total_posts + POSTS_PER_PAGE - 1) // POSTS_PER_PAGE

    # 현재 페이지의 게시글만 선택
    start_idx = (page - 1) * POSTS_PER_PAGE
    end_idx = start_idx + POSTS_PER_PAGE
    current_posts = filtered_posts[start_idx:end_idx]

    return render_template('board.html', 
                         posts=current_posts, 
                         search_query=search_query,
                         current_page=page,
                         total_pages=total_pages)

@app.route('/board/write', methods=['GET', 'POST'])
@login_required
def write_post():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        password = request.form.get('password', '').strip()
        
        # 로그인한 사용자의 닉네임을 자동으로 가져옴
        author = users[session['user_id']]['nickname']
        
        if not all([title, content, password]):
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('write_post'))
        
        # 이미지 처리
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':  # 파일이 선택되었는지 확인
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_url = f"uploads/{filename}"
                else:
                    flash('허용되지 않는 파일 형식입니다.')
                    return redirect(url_for('write_post'))
        
        # 내용 검사
        is_valid, message = check_content(title + " " + content)
        if not is_valid:
            flash(message)
            return redirect(url_for('write_post'))
        
        # 도배 검사
        user_ip = request.remote_addr
        can_post, message = check_spam_activity(
            POST_HISTORY, user_ip, content, POST_INTERVAL, MAX_POSTS_PER_DAY
        )
        if not can_post:
            flash(message)
            return redirect(url_for('write_post'))
        
        content = content.replace('\n', '<br>')
        
        post = {
            'id': len(posts) + 1,
            'title': title,
            'content': content,
            'author': author,
            'username': session['user_id'],  # 작성자의 username 저장
            'password': password,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'views': 0,
            'image_url': image_url
        }
        posts.append(post)
        return redirect(url_for('board'))
    
    return render_template('write_post.html')

@app.route('/board/post/<int:post_id>')
def view_post(post_id):
    post = next((post for post in posts if post['id'] == post_id), None)
    if post:
        post['views'] += 1
        # 해당 게시글의 댓글 목록을 함께 전달
        post_comments = [c for c in comments if c['post_id'] == post_id]
        return render_template('view_post.html', post=post, comments=post_comments)
    return redirect(url_for('board'))

@app.route('/board/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    global posts, comments
    post = next((p for p in posts if p['id'] == post_id), None)
    if post:
        password = request.form.get('password', '')
        if password == post['password']:
            # 게시글 삭제
            posts = [p for p in posts if p['id'] != post_id]
            # 해당 게시글의 댓글도 삭제
            comments = [c for c in comments if c['post_id'] != post_id]
            flash('게시글이 삭제되었습니다.')
        else:
            flash('비밀번호가 일치하지 않습니다.')
    return redirect(url_for('board'))

@app.route('/board/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content', '').strip()
    password = request.form.get('password', '').strip()
    
    # 로그인한 사용자의 닉네임을 자동으로 가져옴
    author = users[session['user_id']]['nickname']
    
    if not all([content, password]):
        flash('모든 필드를 입력해주세요.')
        return redirect(url_for('view_post', post_id=post_id))
        
    # 내용 검사
    is_valid, message = check_content(content)
    if not is_valid:
        flash(message)
        return redirect(url_for('view_post', post_id=post_id))
    
    # 도배 검사
    user_ip = request.remote_addr
    can_comment, message = check_spam_activity(
        COMMENT_HISTORY, user_ip, content, COMMENT_INTERVAL, MAX_COMMENTS_PER_DAY
    )
    if not can_comment:
        flash(message)
        return redirect(url_for('view_post', post_id=post_id))
        
    comment = {
        'id': len(comments) + 1,
        'post_id': post_id,
        'content': content,
        'author': author,
        'username': session['user_id'],  # 작성자의 username 저장
        'password': password,
        'date': datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    comments.append(comment)
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/board/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    global comments
    comment = next((c for c in comments if c['id'] == comment_id), None)
    if comment:
        password = request.form.get('password', '')
        if password == comment['password']:
            post_id = comment['post_id']
            comments = [c for c in comments if c['id'] != comment_id]
            flash('댓글이 삭제되었습니다.')
            return redirect(url_for('view_post', post_id=post_id))
        else:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('view_post', post_id=comment['post_id']))
    return redirect(url_for('board'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        nickname = request.form.get('nickname')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # 아이디 중복 검사
        if username in users:
            flash('이미 사용 중인 아이디입니다.')
            return redirect(url_for('register'))
        
        # 닉네임 중복 검사
        if any(user.get('nickname') == nickname for user in users.values()):
            flash('이미 사용 중인 닉네임입니다.')
            return redirect(url_for('register'))
        
        # 이메일 중복 검사
        if any(user.get('email') == email for user in users.values()):
            flash('이미 사용 중인 이메일입니다.')
            return redirect(url_for('register'))
        
        # 아이디 유효성 검사 (4-20자의 영문자와 숫자)
        if not re.match(r'^[a-zA-Z0-9]{4,20}$', username):
            flash('아이디는 4-20자의 영문자와 숫자만 사용 가능합니다.')
            return redirect(url_for('register'))
        
        # 닉네임 유효성 검사 (2-10자)
        if not 2 <= len(nickname) <= 10:
            flash('닉네임은 2-10자로 입력해주세요.')
            return redirect(url_for('register'))
        
        # 이메일 유효성 검사
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('올바른 이메일 형식이 아닙니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 유효성 검사 (영문 대소문자, 숫자 포함 6자 이상)
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{6,}$', password):
            flash('비밀번호는 영 대소문자와 숫자를 포함하여 6자 이상이어야 합니다.')
            return redirect(url_for('register'))
        
        # 모든 검사를 통과하면 사용자 등록
        users[username] = {
            'password': generate_password_hash(password),
            'email': email,
            'nickname': nickname
        }
        
        flash('회원가입이 완료되었습니다. 로그인해주세요.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:  # 이미 로그인된 경우 홈으로 리다이렉트
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')  # 로그인 유지 체크
        
        if username in users and check_password_hash(users[username]['password'], password):
            session.permanent = True  # 세션을 영구적으로 설정
            session['user_id'] = username
            flash('로그인되었습니다.')
            return redirect(url_for('home'))
        
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # 모든 세션 데이터 삭제
    flash('로그아웃되었습니다.')
    return redirect(url_for('home'))

@app.context_processor
def utility_processor():
    return {
        'users': users  # 모든 템플릿에서 users 수 사용 가능
    }

# 임시 비밀번호 생성 함수
def generate_temp_password():
    return ''.join(random.choices(string.digits, k=6))  # 6자리 숫자

@app.route('/find-id')
def find_id():
    # 등록된 모든 아이디 목록 (닉네임과 함께 표시)
    user_list = [
        {'username': username, 'nickname': data['nickname']} 
        for username, data in users.items()
    ]
    return render_template('find_id.html', users=user_list)

@app.route('/find-password', methods=['GET', 'POST'])
def find_password():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        
        print(f"입력된 정보 - 아이디: {username}, 이메일: {email}")  # 디버깅용
        print(f"현재 사용자 목록: {users}")  # 디버깅용
        
        if username in users:
            stored_email = users[username].get('email')
            print(f"저장된 이메일: {stored_email}")  # 디버깅용
            
            if stored_email == email:
                # 임시 비밀번호 생성
                temp_password = generate_temp_password()
                # 비밀번호 업데이트
                users[username]['password'] = generate_password_hash(temp_password)
                
                flash(f'임시 비밀번호가 발급되었습니다: {temp_password}')
                return redirect(url_for('login'))
            else:
                flash('이메일 주소가 일치하지 않습니다.')
        else:
            flash('존재하지 않는 아이디입니다.')
            
    return render_template('find_password.html')

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required  # 로그인 필요
def withdraw():
    if request.method == 'POST':
        username = session['user_id']
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username]['password'], password):
            # 사용자 관련 데이터 삭제
            # 게시글과 댓글은 남겨기
            del users[username]
            session.pop('user_id', None)
            flash('회원탈퇴가 완료되었습니다.')
            return redirect(url_for('home'))
        else:
            flash('비밀번호가 일치하지 않습니다.')
    
    return render_template('withdraw.html')

@app.route('/check-duplicate')
def check_duplicate():
    field = request.args.get('field')
    value = request.args.get('value')
    
    if field == 'username':
        exists = value in users
    elif field == 'nickname':
        exists = any(user.get('nickname') == value for user in users.values())
    elif field == 'email':
        exists = any(user.get('email') == value for user in users.values())
    else:
        exists = False
        
    return jsonify({'exists': exists})

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    user_data = users[user_id]
    
    # 사용자의 게시글 수 계산
    user_posts = [post for post in posts if post['author'] == user_data['nickname']]
    post_count = len(user_posts)
    
    # 사용자의 댓글 수 계산
    user_comments = [comment for comment in comments if comment['author'] == user_data['nickname']]
    comment_count = len(user_comments)
    
    return render_template('profile.html', 
                         user=user_data,
                         user_id=user_id,  # user_id 추가
                         post_count=post_count,
                         comment_count=comment_count,
                         recent_posts=user_posts[-5:],
                         profile_comments=profile_comments)  # profile_comments 추가

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session['user_id']
    
    if request.method == 'POST':
        new_nickname = request.form.get('nickname', '').strip()
        bio = request.form.get('bio', '').strip()  # 자기소개 가져오기
        
        # 닉네임 중복 확인 (현재 사용자 제외)
        if new_nickname != users[user_id]['nickname'] and \
           any(user.get('nickname') == new_nickname for uid, user in users.items() if uid != user_id):
            flash('이미 사용 중인 닉네임입니다.')
            return redirect(url_for('edit_profile'))
        
        # 프로필 이미지 처리
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"profile_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                users[user_id]['profile_image'] = f"uploads/{filename}"
        
        # 프로필 업데이트
        users[user_id]['nickname'] = new_nickname
        users[user_id]['bio'] = bio  # 자기소개 저장
        
        flash('프로필이 성공적으로 수정되었습니다.')
        return redirect(url_for('profile'))
        
    return render_template('edit_profile.html', user=users[user_id])

@app.route('/guest-login')
def guest_login():
    global guest_count
    guest_count += 1
    
    # 게스트 계정 생성
    guest_id = f"{GUEST_PREFIX}{guest_count}"
    guest_nickname = f"게스트{guest_count}"
    
    # 게스트 계정 정보 저장
    users[guest_id] = {
        'nickname': guest_nickname,
        'email': f"{guest_id}@guest.com",
        'is_guest': True  # 게스트 계정 표시
    }
    
    # 세션에 게스트 로그인 정보 저장
    session['user_id'] = guest_id
    session.permanent = False  # 게스트 세션은 브라우저 종료시 만료
    
    flash('게스트로 로그인되었습니다.')
    return redirect(url_for('home'))

@app.route('/user/<username>')
def user_profile(username):
    if username in users:
        user_data = users[username]
        # 해당 사용자의 게시글 수 계산
        user_posts = [post for post in posts if post['author'] == user_data['nickname']]
        post_count = len(user_posts)
        
        # 해당 사용자의 댓글 수 계산
        user_comments = [comment for comment in comments if comment['author'] == user_data['nickname']]
        comment_count = len(user_comments)
        
        return render_template('user_profile.html', 
                             username=username,
                             user=user_data, 
                             post_count=post_count,
                             comment_count=comment_count,
                             recent_posts=user_posts[-5:])
    return redirect(url_for('board'))

@app.route('/user/<username>/comment', methods=['POST'])
@login_required
def add_profile_comment(username):
    if username not in users:
        return redirect(url_for('board'))
    
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('댓글 내용을 입력해주세요.')
        return redirect(url_for('user_profile', username=username))
    
    # 내용 검사
    is_valid, message = check_content(content)
    if not is_valid:
        flash(message)
        return redirect(url_for('user_profile', username=username))
    
    # 도배 검사
    user_ip = request.remote_addr
    can_comment, message = check_spam_activity(
        COMMENT_HISTORY, user_ip, content, COMMENT_INTERVAL, MAX_COMMENTS_PER_DAY
    )
    if not can_comment:
        flash(message)
        return redirect(url_for('user_profile', username=username))
    
    comment = {
        'id': len(profile_comments) + 1,
        'profile_username': username,  # 프로필 주인의 username
        'content': content,
        'author': users[session['user_id']]['nickname'],  # 댓글 작성자 닉네임
        'author_username': session['user_id'],  # 댓글 작성자 username
        'date': datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    
    profile_comments.append(comment)
    return redirect(url_for('user_profile', username=username))

@app.route('/user/<username>/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_profile_comment(username, comment_id):
    comment = next((c for c in profile_comments if c['id'] == comment_id), None)
    # 댓글 작성자나 프로필 주인만 삭제 가능
    if comment and (comment['author_username'] == session['user_id'] or username == session['user_id']):
        profile_comments.remove(comment)
        flash('댓글이 삭제되었습니다.')
    return redirect(url_for('user_profile', username=username))

if __name__ == '__main__':
    app.run(debug=True) 
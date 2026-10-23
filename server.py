import http.server
import socketserver
from urllib.parse import parse_qs

PORT = 8000

class PhishingDemoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # عرض صفحة تسجيل دخول تجريبية بسيطة جداً
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>صفحة اختبار تجريبية</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; background-color: #f4f4f9; }
                .login-box { display: inline-block; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                input { display: block; margin: 10px auto; padding: 10px; width: 200px; }
                button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>تسجيل الدخول (اختبار محلي)</h2>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="اسم المستخدم" required>
                    <input type="password" name="password" placeholder="كلمة المرور" required>
                    <button type="submit">دخول</button>
                </form>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))

    def do_POST(self):
        # التقاط البيانات التي يكتبها المستخدم وطباعتها في التيرمينال
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed_data = parse_qs(post_data)
        
        username = parsed_data.get('username', [''])[0]
        password = parsed_data.get('password', [''])[0]

        print("\n" + "="*40)
        print("🚨 [تم التقاط بيانات تجريبية بنجاح!] 🚨")
        print(f"👤 اسم المستخدم: {username}")
        print(f"🔑 كلمة المرور: {password}")
        print("="*40 + "\n")

        # إرجاع رد للضحية
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        response_text = "<h2>شكراً لك! تم تسجيل الدخول (هذه تجربة تعليمية بنجاح).</h2>"
        self.wfile.write(response_text.encode('utf-8'))

with socketserver.TCPServer(("", PORT), PhishingDemoHandler) as httpd:
    print(f"🌐 السيرفر المحلي يعمل الآن على: http://localhost:{PORT}")
    print("بانتظار أي محاولة دخول...")
    httpd.serve_forever()
import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
)
from werkzeug.utils import secure_filename
from analyzer import analyze_pcap
from xhtml2pdf import pisa  # PDF generator [web:146][web:158][web:161]
import io

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# store last analysis in memory so we can reuse it for PDF
LAST_RESULTS = None
LAST_FILENAME = None

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def index():
    global LAST_RESULTS, LAST_FILENAME

    if request.method == "POST":
        if "file" not in request.files:
            return "No file part", 400
        file = request.files["file"]
        if file.filename == "":
            return "No selected file", 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            results = analyze_pcap(save_path)

            LAST_RESULTS = results
            LAST_FILENAME = filename

            return render_template("index.html", results=results, filename=filename)
        else:
            return "Invalid file type. Upload .pcap or .pcapng", 400

    return render_template("index.html", results=LAST_RESULTS, filename=LAST_FILENAME)

@app.route("/download_pdf")
def download_pdf():
    """
    Generate a PDF version of the latest report and send as download.
    """
    if not LAST_RESULTS or not LAST_FILENAME:
        return redirect(url_for("index"))

    # Render HTML for PDF (same template, PDF mode on)
    html = render_template(
        "index.html",
        results=LAST_RESULTS,
        filename=LAST_FILENAME,
        pdf_mode=True,
    )

    # Convert HTML to PDF into a memory buffer
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_buffer)  # standard xhtml2pdf usage [web:146][web:158][web:161]

    if pisa_status.err:
        return "Error generating PDF", 500

    pdf_buffer.seek(0)
    pdf_filename = f"{os.path.splitext(LAST_FILENAME)[0]}_report.pdf"

    response = make_response(pdf_buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={pdf_filename}"
    return response

if __name__ == "__main__":
    app.run(debug=True)

"""Generate synthetic sample screenshot images for offline demo testing."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def create_demo_screenshots():
    out_dir = Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create a simulated phishing alert screenshot
    img1 = Image.new("RGB", (650, 260), color=(248, 249, 250))
    draw1 = ImageDraw.Draw(img1)

    # Header bar
    draw1.rectangle([(0, 0), (650, 45)], fill=(220, 53, 69))
    draw1.text((20, 12), "SECURITY ALERT: Account Suspension Warning", fill=(255, 255, 255))

    # Content
    draw1.text((20, 60), "Your Microsoft 365 account has suspicious activity.", fill=(33, 37, 41))
    draw1.text((20, 90), "Immediate action required within 24 hours to prevent locked account.", fill=(220, 53, 69))
    draw1.text((20, 120), "Please verify your password and identity now:", fill=(33, 37, 41))
    draw1.text((20, 150), "http://login.microsoft.security-verify.evil-portal.com/auth", fill=(13, 110, 253))
    draw1.text((20, 190), "IT Security & Compliance Department", fill=(108, 117, 125))

    p1 = out_dir / "phishing_alert_screenshot.png"
    img1.save(p1)
    print(f"Saved: {p1}")

    # 2. Create a simulated clean email screenshot
    img2 = Image.new("RGB", (600, 200), color=(255, 255, 255))
    draw2 = ImageDraw.Draw(img2)
    draw2.rectangle([(0, 0), (600, 40)], fill=(13, 110, 253))
    draw2.text((20, 12), "Team Weekly Sync - Agenda", fill=(255, 255, 255))
    draw2.text((20, 60), "Hi everyone, here is the agenda for our project review meeting.", fill=(33, 37, 41))
    draw2.text((20, 90), "Please review the slides attached in the documentation repository.", fill=(33, 37, 41))
    draw2.text((20, 130), "Thanks,\nProject Lead", fill=(108, 117, 125))

    p2 = out_dir / "clean_message_screenshot.png"
    img2.save(p2)
    print(f"Saved: {p2}")


if __name__ == "__main__":
    create_demo_screenshots()

FROM python:3.11.5-slim
RUN apt update && apt install -y nmap
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD [ "python3" , "kiro.py" ]
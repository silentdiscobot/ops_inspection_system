FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-wqy-zenhei \
    fonts-wqy-microhei \
    fonts-dejavu \
    fonts-freefont-ttf \
    fontconfig \
    && fc-cache -fv \
    && fc-list | grep -i -E "(wqy|dejavu|freefont)" \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs reports data

EXPOSE 1999

ENV OPS_DEBUG=0
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

CMD ["python", "app.py"]
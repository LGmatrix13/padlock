# Use an official Python runtime as a parent image
FROM python

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Make port 500 available to the world outside this container
EXPOSE 5000

# Run app.py when the container launches
CMD [ "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app" ]
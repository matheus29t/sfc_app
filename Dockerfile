FROM alpine
WORKDIR /
ENV PATH="/usr/share/openvswitch/scripts/:${PATH}" 
RUN apk add --no-cache openvswitch &&\
apk add --no-cache python3
ADD boot.sh / 
ADD json_register.py /
ENTRYPOINT ["/boot.sh" ]






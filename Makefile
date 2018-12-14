runnerpath = .
runnertag = dev

runner/build/docker:
	docker build $(runnerpath) -t taask/runner-k8s:$(runnertag)
package main

import (
	"encoding/json"
	"syscall/js"
)

func main() {
	done := make(chan struct{})
	call := js.FuncOf(func(this js.Value, args []js.Value) any {
		input := args[0].String()
		executor := js.FuncOf(func(this js.Value, callbacks []js.Value) any {
			resolve, reject := callbacks[0], callbacks[1]
			go func() {
				var req request
				if err := json.Unmarshal([]byte(input), &req); err != nil {
					reject.Invoke(err.Error())
					return
				}
				output, err := json.Marshal(handle(req))
				if err != nil {
					reject.Invoke(err.Error())
					return
				}
				resolve.Invoke(string(output))
			}()
			return nil
		})
		promise := js.Global().Get("Promise").New(executor)
		executor.Release()
		return promise
	})
	stop := js.FuncOf(func(this js.Value, args []js.Value) any {
		close(done)
		return nil
	})
	js.Global().Set("tscProbeInvoke", call)
	js.Global().Set("tscProbeClose", stop)
	<-done
	call.Release()
	stop.Release()
}
